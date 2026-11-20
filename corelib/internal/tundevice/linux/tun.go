//go:build linux

// Package tun borrows an existing Linux TUN device by file descriptor. Creating
// the device, its addresses, routes and DNS settings stays with the privileged
// network helper; the core only verifies and owns the raw IPv4 queue.
package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"

	deviceaddr "github.com/wtalioy/JustConnect/corelib/internal/tundevice/address"
	"golang.org/x/sys/unix"
)

// Linux TUN creation flags; the helper must hand over an IPv4, headerless queue.
const (
	tunFlagsRequired  = unix.IFF_TUN | unix.IFF_NO_PI
	tunFlagsForbidden = unix.IFF_TAP | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE
)

type Device struct {
	*os.File
	local, peer netip.Addr
}

func (d *Device) TUNAddresses() (netip.Addr, netip.Addr) { return d.local, d.peer }

// Duplicate borrows a nonblocking TUN file descriptor and retains the device's
// IPv4 point-to-point address pair.
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
	request, err := unix.NewIfreq("")
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlIfreq(copied, unix.TUNGETIFF, request); err != nil {
		return nil, err
	}
	name := request.Name()
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, unix.EINVAL
	}
	created := request.Uint16()
	if created&tunFlagsRequired != tunFlagsRequired || created&tunFlagsForbidden != 0 {
		return nil, unix.EINVAL
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if uint32(link.MTU) != mtu || link.Flags&net.FlagUp == 0 {
		return nil, unix.EINVAL
	}
	local, peer, err := addresses(link.Index)
	if err != nil {
		return nil, err
	}
	if !deviceaddr.ValidIPv4Pair(local, peer) {
		return nil, unix.EINVAL
	}
	file := os.NewFile(uintptr(copied), name)
	if file == nil {
		return nil, unix.EBADF
	}
	owned = true
	return &Device{File: file, local: local, peer: peer}, nil
}

// addresses reads the IPv4 point-to-point pair from the kernel address table.
// A peer address travels as IFA_ADDRESS next to IFA_LOCAL; a plain interface
// address carries both as the same value and cannot serve the tunnel contract.
func addresses(index int) (netip.Addr, netip.Addr, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_INET)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	var local, peer netip.Addr
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(message.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		// struct ifaddrmsg: family, prefixlen, flags, scope, then the 32-bit index.
		if int(binary.LittleEndian.Uint32(message.Data[4:8])) != index {
			continue
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			continue
		}
		var candidate, destination netip.Addr
		for _, attribute := range attributes {
			value, ok := netip.AddrFromSlice(attribute.Value)
			if !ok {
				continue
			}
			switch attribute.Attr.Type {
			case unix.IFA_LOCAL:
				candidate = value.Unmap()
			case unix.IFA_ADDRESS:
				destination = value.Unmap()
			}
		}
		if !candidate.IsValid() {
			candidate = destination
		}
		if !candidate.IsValid() || local.IsValid() {
			continue
		}
		local = candidate
		if destination.IsValid() && destination != candidate {
			peer = destination
		}
	}
	if !local.IsValid() {
		return netip.Addr{}, netip.Addr{}, errors.New("TUN device has no IPv4 address")
	}
	return local, peer, nil
}

func (d *Device) Read(packet []byte) (int, error) {
	for {
		n, err := d.File.Read(packet)
		if err != nil {
			return 0, err
		}
		// IPv4 only: the helper installs no IPv6 address, so the core also
		// never offers IPv6 forwarding on this device. Unsupported frames are
		// dropped and the read continues, so one stray packet cannot end the
		// shared read loop with EINVAL.
		if n < 20 || packet[0]>>4 != 4 {
			continue
		}
		return n, nil
	}
}

func (d *Device) Write(packet []byte) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, unix.EINVAL
	}
	n, err := d.File.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
