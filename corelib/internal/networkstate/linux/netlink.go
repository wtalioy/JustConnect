//go:build linux

package networkstate

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// netlinkMessages reads one routing-table dump. The stdlib helper performs the
// socket dance (bind, request, drain until NLMSG_DONE) that the net package
// itself uses, so no hand-rolled buffer growth is duplicated here.
func netlinkMessages(message uint16, family int) ([]syscall.NetlinkMessage, error) {
	rib, err := syscall.NetlinkRIB(int(message), family)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	return messages, nil
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
	multipath   bool
}

func addressOf(value []byte) netip.Addr {
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return netip.Addr{}
	}
	return address.Unmap()
}

func littleEndianUint32(value []byte) uint32 {
	if len(value) < 4 {
		return 0
	}
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24
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
		flags:    littleEndianUint32(header[rtFieldFlags : rtFieldFlags+4]),
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
			row.index = int(littleEndianUint32(attribute.Value))
		case unix.RTA_PRIORITY:
			row.metric = littleEndianUint32(attribute.Value)
		case unix.RTA_TABLE:
			row.table = uint16(littleEndianUint32(attribute.Value))
		case unix.RTA_MULTIPATH:
			row.multipath = true
		}
	}
	// Multi-path entries carry per-hop metadata only; the first hop owns the
	// forwarding decision, so a plain row cannot describe it.
	if row.multipath && row.index == 0 {
		if hop, ok := firstNexthop(attributes); ok {
			row.index, row.gateway = hop.index, hop.gateway
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
}

// firstNexthop decodes RTA_MULTIPATH (struct rtnexhop): per-hop length, flags,
// weight, interface index and the family-sized gateway address.
func firstNexthop(attributes []syscall.NetlinkRouteAttr) (nexthop, bool) {
	for _, attribute := range attributes {
		if attribute.Attr.Type != unix.RTA_MULTIPATH {
			continue
		}
		value := attribute.Value
		if len(value) < 8 {
			return nexthop{}, false
		}
		length := int(value[0]) | int(value[1])<<8
		if length < 8 || length > len(value) {
			return nexthop{}, false
		}
		hop := nexthop{index: int(littleEndianUint32(value[4:8]))}
		if remaining := value[8:length]; len(remaining) == 4 {
			hop.gateway = addressOf(remaining)
		} else if len(remaining) == 16 {
			hop.gateway = addressOf(remaining)
		} else if len(remaining) != 0 {
			return nexthop{}, false
		}
		return hop, true
	}
	return nexthop{}, false
}
