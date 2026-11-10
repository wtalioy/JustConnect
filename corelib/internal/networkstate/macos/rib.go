//go:build darwin

package networkstate

import (
	"errors"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func routeAddress(value route.Addr) net.IP {
	switch address := value.(type) {
	case *route.Inet4Addr:
		return net.IP(address.IP[:])
	case *route.Inet6Addr:
		return net.IP(address.IP[:])
	}
	return nil
}

func routingMessages() ([]route.Message, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	return route.ParseRIB(route.RIBTypeRoute, rib)
}

func defaultIPv4RouteIndex(messages []route.Message) int {
	const required = unix.RTF_UP | unix.RTF_GATEWAY
	for _, message := range messages {
		row, ok := message.(*route.RouteMessage)
		if !ok || row.Flags&required != required || len(row.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		destination, isIPv4 := row.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		mask, isIPv4Mask := row.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if isIPv4 && isIPv4Mask && destination.IP == ([4]byte{}) && mask.IP == ([4]byte{}) {
			return row.Index
		}
	}
	return 0
}

func DefaultIPv4Interface() string {
	messages, err := routingMessages()
	if err != nil {
		return ""
	}
	if index := defaultIPv4RouteIndex(messages); index != 0 {
		if iface, err := net.InterfaceByIndex(index); err == nil {
			return iface.Name
		}
	}
	return ""
}

func ReadRoutes() ([]model.Route, error) {
	messages, err := routingMessages()
	if err != nil {
		return nil, err
	}
	routes := make([]model.Route, 0, len(messages))
	for _, message := range messages {
		row, ok := message.(*route.RouteMessage)
		if !ok || len(row.Addrs) <= unix.RTAX_DST {
			continue
		}
		address, ok := netip.AddrFromSlice(routeAddress(row.Addrs[unix.RTAX_DST]))
		if !ok {
			continue
		}
		bits := 0
		if row.Flags&unix.RTF_HOST != 0 {
			bits = address.BitLen()
		} else if len(row.Addrs) > unix.RTAX_NETMASK && row.Addrs[unix.RTAX_NETMASK] != nil {
			mask := routeAddress(row.Addrs[unix.RTAX_NETMASK])
			var total int
			bits, total = net.IPMask(mask).Size()
			if total != address.BitLen() {
				return nil, errors.New("non-contiguous native route mask")
			}
		} else if !address.IsUnspecified() {
			return nil, errors.New("missing native route mask")
		}
		item := model.Route{Destination: netip.PrefixFrom(address, bits).Masked().String(), InterfaceIndex: row.Index, Flags: row.Flags, Cloned: row.Flags&unix.RTF_WASCLONED != 0}
		if len(row.Addrs) > unix.RTAX_GATEWAY {
			if gateway := routeAddress(row.Addrs[unix.RTAX_GATEWAY]); gateway != nil {
				item.Gateway = gateway.String()
			}
		}
		routes = append(routes, item)
	}
	return routes, nil
}
