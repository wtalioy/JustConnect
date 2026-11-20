//go:build linux

package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net"

	"golang.org/x/sys/unix"
)

// DefaultIPv4Interface mirrors the macOS exit selection: the lowest-metric
// gatewayed default route of the main table decides where new connections go.
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
		if err != nil || row.family != unix.AF_INET || row.destination.Bits() != 0 || row.index <= 0 {
			continue
		}
		if row.table != main || row.gateway.IsUnspecified() {
			continue
		}
		if best.index == 0 || row.metric < best.metric {
			best.index, best.metric = row.index, row.metric
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
		switch row.family {
		case unix.AF_INET, unix.AF_INET6:
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
		routes = append(routes, item)
	}
	return routes, nil
}
