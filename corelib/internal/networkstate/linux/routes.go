//go:build linux

package networkstate

import (
	"net"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/unix"
)

// DefaultIPv4Interface returns an available next hop on the lowest-metric main-table default.
func DefaultIPv4Interface() string {
	messages, err := netlinkMessages(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return ""
	}
	const main = uint16(unix.RT_TABLE_MAIN)
	best := struct {
		index  int
		metric uint32
	}{}
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWROUTE {
			continue
		}
		row, err := parseRouteRow(message)
		if err != nil || row.family != unix.AF_INET || row.destination.Bits() != 0 || row.table != main || row.kind != unix.RTN_UNICAST {
			continue
		}
		index, gateway := row.index, row.gateway
		for _, hop := range row.nexthops {
			if hop.index > 0 && hop.flags&(unix.RTNH_F_DEAD|unix.RTNH_F_LINKDOWN) == 0 && !hop.gateway.IsUnspecified() {
				index, gateway = hop.index, hop.gateway
				break
			}
		}
		if index <= 0 || gateway.IsUnspecified() {
			continue
		}
		if best.index == 0 || row.metric < best.metric {
			best.index, best.metric = index, row.metric
		}
	}
	if best.index == 0 {
		return ""
	}
	if iface, err := net.InterfaceByIndex(best.index); err == nil {
		return iface.Name
	}
	return ""
}

// ReadRoutes keeps the usable kernel route kinds. Blackhole, prohibit,
// unreachable and throw entries describe policy, not reachable networks.
func ReadRoutes() ([]model.Route, error) {
	messages, err := netlinkMessages(unix.RTM_GETROUTE, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	routes := make([]model.Route, 0, len(messages))
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWROUTE {
			continue
		}
		row, err := parseRouteRow(message)
		if err != nil {
			continue
		}
		switch row.kind {
		case unix.RTN_UNICAST, unix.RTN_LOCAL, unix.RTN_BROADCAST, unix.RTN_MULTICAST, unix.RTN_ANYCAST, unix.RTN_NAT:
		default:
			continue
		}
		item := model.Route{
			Destination:    row.destination.String(),
			InterfaceIndex: row.index,
			Gateway:        row.gateway.String(),
			Metric:         int(row.metric),
			Protocol:       int(row.protocol),
			Flags:          int(row.flags),
			Cloned:         row.cloned,
		}
		if len(row.nexthops) == 0 {
			routes = append(routes, item)
			continue
		}
		for _, hop := range row.nexthops {
			if hop.index > 0 {
				item.InterfaceIndex, item.Gateway = hop.index, hop.gateway.String()
				routes = append(routes, item)
			}
		}
	}
	return routes, nil
}
