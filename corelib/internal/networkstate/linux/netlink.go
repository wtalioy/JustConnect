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
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return routeRow{}, err
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
	for _, attribute := range attributes {
		switch attribute.Attr.Type {
		case unix.RTA_DST:
			destination = addressOf(attribute.Value)
		case unix.RTA_GATEWAY:
			row.gateway = addressOf(attribute.Value)
		case unix.RTA_OIF:
			row.index = int(netlinkUint32(attribute.Value))
		case unix.RTA_PRIORITY:
			row.metric = netlinkUint32(attribute.Value)
		case unix.RTA_TABLE:
			row.table = uint16(netlinkUint32(attribute.Value))
		case unix.RTA_MULTIPATH:
			row.nexthops, err = parseNexthops(attribute.Value)
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
			if len(attrs) < unix.SizeofRtAttr {
				return nil, errors.New("short netlink nexthop attribute")
			}
			size := int(binary.NativeEndian.Uint16(attrs))
			step := (size + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
			if size < unix.SizeofRtAttr || step > len(attrs) {
				return nil, errors.New("invalid netlink nexthop attribute length")
			}
			if binary.NativeEndian.Uint16(attrs[2:]) == unix.RTA_GATEWAY {
				hop.gateway = addressOf(attrs[unix.SizeofRtAttr:size])
				if !hop.gateway.IsValid() {
					return nil, errors.New("invalid netlink nexthop gateway")
				}
			}
			attrs = attrs[step:]
		}
		hops = append(hops, hop)
		value = value[aligned:]
	}
	return hops, nil
}
