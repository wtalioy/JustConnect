//go:build linux

package networkstate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// netlinkMessages reads one netlink dump. The stdlib helper performs the
// socket dance (bind, request, drain until NLMSG_DONE) that the net package
// itself uses, so no hand-rolled buffer growth is duplicated here.
func netlinkMessages(message uint16, family int) ([]syscall.NetlinkMessage, error) {
	rib, err := syscall.NetlinkRIB(int(message), family)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(rib)
}

func nextAttribute(data []byte) (kind uint16, value, rest []byte, err error) {
	if len(data) < unix.SizeofRtAttr {
		return 0, nil, nil, errors.New("short netlink attribute")
	}
	length := int(binary.NativeEndian.Uint16(data))
	aligned := (length + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
	if length < unix.SizeofRtAttr || aligned > len(data) {
		return 0, nil, nil, errors.New("invalid netlink attribute length")
	}
	return binary.NativeEndian.Uint16(data[2:]), data[unix.SizeofRtAttr:length], data[aligned:], nil
}

// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type,
// then a 32-bit flag word.
const (
	rtFieldTable    = 4
	rtFieldProtocol = 5
	rtFieldType     = 7
	rtFieldFlags    = 8
)

type routeRow struct {
	family      uint8
	destination netip.Prefix
	gateway     netip.Addr
	index       int
	metric      uint32
	table       uint16
	protocol    uint8
	kind        uint8
	flags       uint32
	cloned      bool
	nexthops    []nexthop
}

func addressOf(value []byte) netip.Addr {
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return netip.Addr{}
	}
	return address.Unmap()
}

func netlinkUint32(value []byte) uint32 {
	if len(value) < 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(value)
}

func parseRouteRow(message syscall.NetlinkMessage) (routeRow, error) {
	if len(message.Data) < unix.SizeofRtMsg {
		return routeRow{}, errors.New("short netlink route message")
	}
	header := message.Data[:unix.SizeofRtMsg]
	row := routeRow{
		family:   header[0],
		protocol: header[rtFieldProtocol],
		kind:     header[rtFieldType],
		flags:    netlinkUint32(header[rtFieldFlags : rtFieldFlags+4]),
	}
	var destination netip.Addr
	switch row.family {
	case unix.AF_INET:
		destination = netip.AddrFrom4([4]byte{})
		if bits := int(header[1]); bits > 32 {
			return routeRow{}, fmt.Errorf("invalid IPv4 route prefix length %d", bits)
		}
	case unix.AF_INET6:
		destination = netip.AddrFrom16([16]byte{})
		if bits := int(header[1]); bits > 128 {
			return routeRow{}, fmt.Errorf("invalid IPv6 route prefix length %d", bits)
		}
	default:
		return routeRow{}, fmt.Errorf("unsupported route family %d", row.family)
	}
	bits := int(header[1])
	for attrs := message.Data[unix.SizeofRtMsg:]; len(attrs) > 0; {
		kind, value, rest, err := nextAttribute(attrs)
		if err != nil {
			return routeRow{}, err
		}
		attrs = rest
		switch kind {
		case unix.RTA_DST:
			destination = addressOf(value)
		case unix.RTA_GATEWAY:
			row.gateway = addressOf(value)
		case unix.RTA_OIF:
			row.index = int(netlinkUint32(value))
		case unix.RTA_PRIORITY:
			row.metric = netlinkUint32(value)
		case unix.RTA_TABLE:
			row.table = uint16(netlinkUint32(value))
		case unix.RTA_MULTIPATH:
			row.nexthops, err = parseNexthops(value)
			if err != nil {
				return routeRow{}, err
			}
		}
	}
	row.destination = netip.PrefixFrom(destination, bits).Masked()
	if row.table == 0 {
		row.table = uint16(header[rtFieldTable])
	}
	row.cloned = row.flags&unix.RTM_F_CLONED != 0
	return row, nil
}

type nexthop struct {
	index   int
	gateway netip.Addr
	flags   byte
}

func parseNexthops(value []byte) ([]nexthop, error) {
	var hops []nexthop
	for len(value) > 0 {
		if len(value) < unix.SizeofRtNexthop {
			return nil, errors.New("short netlink nexthop")
		}
		length := int(binary.NativeEndian.Uint16(value))
		aligned := (length + unix.RTNH_ALIGNTO - 1) &^ (unix.RTNH_ALIGNTO - 1)
		if length < unix.SizeofRtNexthop || aligned > len(value) {
			return nil, errors.New("invalid netlink nexthop length")
		}
		hop := nexthop{index: int(int32(binary.NativeEndian.Uint32(value[4:8]))), flags: value[2]}
		// Gateways are RTA_GATEWAY attributes nested inside each rtnexthop.
		for attrs := value[unix.SizeofRtNexthop:length]; len(attrs) > 0; {
			kind, attribute, rest, err := nextAttribute(attrs)
			if err != nil {
				return nil, err
			}
			if kind == unix.RTA_GATEWAY {
				hop.gateway = addressOf(attribute)
				if !hop.gateway.IsValid() {
					return nil, errors.New("invalid netlink nexthop gateway")
				}
			}
			attrs = rest
		}
		hops = append(hops, hop)
		value = value[aligned:]
	}
	return hops, nil
}
