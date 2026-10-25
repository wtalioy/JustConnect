//go:build darwin

package networkstate

import (
	"errors"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/networkstate/model"
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

func ReadRoutes(_ []model.Interface) ([]model.Route, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	routes := []model.Route{}
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
