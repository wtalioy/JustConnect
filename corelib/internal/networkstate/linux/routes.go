//go:build linux

package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func ReadRoutes(_ []model.Interface) ([]model.Route, error) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if err := handle.SetSocketTimeout(time.Second); err != nil {
		return nil, err
	}
	// Table zero with RT_FILTER_TABLE requests all tables, including Tailscale's.
	native, err := handle.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	routes := []model.Route{}
	for _, row := range native {
		if row.Family != unix.AF_INET && row.Family != unix.AF_INET6 {
			continue
		}
		destination := "0.0.0.0/0"
		if row.Family == unix.AF_INET6 {
			destination = "::/0"
		}
		if row.Dst != nil {
			destination = row.Dst.String()
		}
		item := model.Route{Destination: destination, InterfaceIndex: row.LinkIndex, Table: row.Table, Metric: row.Priority, Scope: int(row.Scope), Protocol: int(row.Protocol), Kind: row.Type, Flags: row.Flags}
		if row.Gw != nil {
			item.Gateway = row.Gw.String()
		}
		if row.Src != nil {
			item.Source = row.Src.IP.String()
		}
		for _, hop := range row.MultiPath {
			value := model.NextHop{InterfaceIndex: hop.LinkIndex, Weight: hop.Hops + 1, Flags: hop.Flags}
			if hop.Gw != nil {
				value.Gateway = hop.Gw.String()
			}
			item.NextHops = append(item.NextHops, value)
		}
		routes = append(routes, item)
	}
	return routes, nil
}
