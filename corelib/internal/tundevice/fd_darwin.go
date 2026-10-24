package tundevice

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const Supported = true

// XNU bsd/net/if_utun.h: framed packets, interface identity and control name.
const (
	utunFlags   = 1
	utunName    = 2
	utunControl = "com.apple.net.utun_control"
	// XNU bsd/sys/sys_domain.h: SYSPROTO_CONTROL is absent from x/sys/unix.
	sysProtoControl = 2
)

type Device struct {
	*os.File
	local, peer netip.Addr
}

func (d *Device) TUNAddresses() (netip.Addr, netip.Addr) { return d.local, d.peer }

func (d *Device) ioError(err error) error {
	// RawConn exposes an internal poller error; preserve os.File's public close contract.
	if err != nil {
		if _, state := d.File.Stat(); errors.Is(state, os.ErrClosed) {
			return os.ErrClosed
		}
	}
	return err
}

// Duplicate borrows a nonblocking utun socket and retains its address-family framing.
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
	var control unix.CtlInfo
	copy(control.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(copied, &control); err != nil {
		return nil, err
	}
	address, err := unix.Getpeername(copied)
	if err != nil {
		return nil, err
	}
	endpoint, ok := address.(*unix.SockaddrCtl)
	if !ok || endpoint.ID != control.Id || endpoint.Unit == 0 {
		return nil, unix.EINVAL
	}
	framing, err := unix.GetsockoptInt(copied, sysProtoControl, utunFlags)
	if err != nil {
		return nil, err
	}
	if framing != 0 {
		return nil, unix.EINVAL
	}
	name, err := unix.GetsockoptString(copied, sysProtoControl, utunName)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(name, "utun") || len(name) >= unix.IFNAMSIZ {
		return nil, unix.EINVAL
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if uint32(link.MTU) != mtu || link.Flags&(net.FlagUp|net.FlagPointToPoint) != net.FlagUp|net.FlagPointToPoint {
		return nil, unix.EINVAL
	}
	local, peer, err := addresses(link.Index)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(copied), name)
	if file == nil {
		return nil, unix.EBADF
	}
	owned = true
	return &Device{File: file, local: local, peer: peer}, nil
}

func addresses(index int) (netip.Addr, netip.Addr, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeInterface, index)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	rows, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	var local, peer netip.Addr
	for _, row := range rows {
		address, ok := row.(*route.InterfaceAddrMessage)
		if !ok || address.Index != index || len(address.Addrs) <= unix.RTAX_BRD {
			continue
		}
		source, ok := address.Addrs[unix.RTAX_IFA].(*route.Inet4Addr)
		if !ok {
			continue
		}
		destination, ok := address.Addrs[unix.RTAX_BRD].(*route.Inet4Addr)
		if !ok || local.IsValid() {
			return netip.Addr{}, netip.Addr{}, unix.EINVAL
		}
		local, peer = netip.AddrFrom4(source.IP), netip.AddrFrom4(destination.IP)
	}
	if !ValidIPv4Pair(local, peer) {
		return netip.Addr{}, netip.Addr{}, unix.EINVAL
	}
	return local, peer, nil
}

func (d *Device) Read(packet []byte) (int, error) {
	connection, err := d.SyscallConn()
	if err != nil {
		return 0, err
	}
	var header [4]byte
	var n, flags int
	var readErr error
	err = connection.Read(func(fd uintptr) bool {
		for {
			n, _, flags, _, readErr = unix.RecvmsgBuffers(int(fd), [][]byte{header[:], packet}, nil, 0)
			if readErr == unix.EINTR {
				continue
			}
			if readErr == unix.EAGAIN {
				return false
			}
			if readErr != nil {
				return true
			}
			if n < len(header) {
				readErr = unix.EINVAL
				return true
			}
			family := binary.BigEndian.Uint32(header[:])
			// utun also emits IPv6 control traffic; this entry serves IPv4 only.
			if family == unix.AF_INET6 {
				continue
			}
			if family != unix.AF_INET || flags&unix.MSG_TRUNC != 0 || n < 24 || len(packet) == 0 || packet[0]>>4 != 4 {
				readErr = unix.EINVAL
			}
			return true
		}
	})
	if err != nil {
		return 0, d.ioError(err)
	}
	if readErr != nil {
		return 0, readErr
	}
	return n - len(header), nil
}

func (d *Device) Write(packet []byte) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, unix.EINVAL
	}
	connection, err := d.SyscallConn()
	if err != nil {
		return 0, err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], unix.AF_INET)
	var n int
	var writeErr error
	err = connection.Write(func(fd uintptr) bool {
		for {
			n, writeErr = unix.SendmsgBuffers(int(fd), [][]byte{header[:], packet}, nil, nil, 0)
			if writeErr != unix.EINTR {
				return writeErr != unix.EAGAIN
			}
		}
	})
	if err != nil {
		return 0, d.ioError(err)
	}
	if writeErr != nil {
		return 0, writeErr
	}
	if n != len(header)+len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(packet), nil
}
