//go:build linux

package tun

import (
	"encoding/binary"
	deviceaddr "github.com/wtalioy/JustConnect/corelib/internal/tundevice/address"
	"net/netip"
	"os"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

type Device struct {
	*os.File
	local, peer netip.Addr
}

func (d *Device) TUNAddresses() (netip.Addr, netip.Addr) { return d.local, d.peer }

// Duplicate borrows a nonblocking raw TUN fd; it never changes the caller's flags.
func Duplicate(fd int, mtu uint32) (*Device, error) {
	copied, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = unix.Close(copied)
		}
	}()
	flags, err := unix.FcntlInt(uintptr(copied), unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	if flags&unix.O_NONBLOCK == 0 || flags&unix.O_ACCMODE != unix.O_RDWR {
		return nil, unix.EINVAL
	}
	request, _ := unix.NewIfreq("")
	if err := unix.IoctlIfreq(copied, unix.TUNGETIFF, request); err != nil {
		return nil, err
	}
	if request.Uint16()&(unix.IFF_TUN|unix.IFF_TAP|unix.IFF_VNET_HDR|unix.IFF_MULTI_QUEUE|unix.IFF_PERSIST) != unix.IFF_TUN {
		return nil, unix.EINVAL
	}
	if err := rawLink(request.Name(), mtu); err != nil {
		return nil, err
	}
	local, peer, err := addresses(request.Name())
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(copied), request.Name())
	if file == nil {
		return nil, unix.EBADF
	}
	owned = true
	return &Device{File: file, local: local, peer: peer}, nil
}

func addresses(name string) (netip.Addr, netip.Addr, error) {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	defer unix.Close(socket)
	read := func(operation uint) (netip.Addr, error) {
		request, err := unix.NewIfreq(name)
		if err == nil {
			err = unix.IoctlIfreq(socket, operation, request)
		}
		if err != nil {
			return netip.Addr{}, err
		}
		value, err := request.Inet4Addr()
		address, valid := netip.AddrFromSlice(value)
		if err == nil && !valid {
			err = unix.EINVAL
		}
		return address, err
	}
	local, err := read(unix.SIOCGIFADDR)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	peer, err := read(unix.SIOCGIFDSTADDR)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if !deviceaddr.ValidIPv4Pair(local, peer) {
		return netip.Addr{}, netip.Addr{}, unix.EINVAL
	}
	return local, peer, nil
}

func attributes(data []byte) (map[uint16][]byte, error) {
	native, err := nl.ParseRouteAttr(data)
	if err != nil {
		return nil, err
	}
	result := make(map[uint16][]byte, len(native))
	for _, attribute := range native {
		result[attribute.Attr.Type&nl.NLA_TYPE_MASK] = attribute.Value
	}
	return result, nil
}

func rawLink(name string, mtu uint32) error {
	socket, err := nl.GetNetlinkSocketAt(-1, -1, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer socket.Close()
	timeout := unix.Timeval{Sec: 1}
	if err := socket.SetSendTimeout(&timeout); err != nil {
		return err
	}
	if err := socket.SetReceiveTimeout(&timeout); err != nil {
		return err
	}
	request := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)
	request.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: socket}}
	request.AddData(nl.NewIfInfomsg(unix.AF_UNSPEC))
	request.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name)))
	rows, err := request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil {
		return err
	}
	if len(rows) != 1 || len(rows[0]) < unix.SizeofIfInfomsg {
		return unix.EINVAL
	}
	message := nl.DeserializeIfInfomsg(rows[0])
	if message.Flags&unix.IFF_UP == 0 {
		return unix.EINVAL
	}
	link, err := attributes(rows[0][unix.SizeofIfInfomsg:])
	if err != nil {
		return err
	}
	if len(link[unix.IFLA_MTU]) != 4 || binary.NativeEndian.Uint32(link[unix.IFLA_MTU]) != mtu {
		return unix.EINVAL
	}
	info, err := attributes(link[unix.IFLA_LINKINFO])
	if err != nil {
		return err
	}
	if string(info[nl.IFLA_INFO_KIND]) != "tun\x00" {
		return unix.EINVAL
	}
	data, err := attributes(info[nl.IFLA_INFO_DATA])
	if err != nil {
		return err
	}
	// TUNGETIFF aliases NO_PI with NOFILTER; netlink carries the actual framing flags.
	for kind, value := range map[uint16]byte{nl.IFLA_TUN_TYPE: unix.IFF_TUN, nl.IFLA_TUN_PI: 0, nl.IFLA_TUN_VNET_HDR: 0, nl.IFLA_TUN_PERSIST: 0, nl.IFLA_TUN_MULTI_QUEUE: 0} {
		if len(data[kind]) != 1 || data[kind][0] != value {
			return unix.EINVAL
		}
	}
	return nil
}
