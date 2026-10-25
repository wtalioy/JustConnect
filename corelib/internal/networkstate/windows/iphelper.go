//go:build windows

package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsAddress(value *windows.RawSockaddrInet) (netip.Addr, bool) {
	address := windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(value)), SockaddrLength: int32(unsafe.Sizeof(*value))}
	ip, ok := netip.AddrFromSlice(address.IP())
	return ip, ok
}

func ReadRoutes(interfaces []model.Interface) ([]model.Route, error) {
	for i := range interfaces {
		row := windows.MibIfRow2{InterfaceIndex: uint32(interfaces[i].Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
			return nil, err
		}
		interfaces[i].Description = windows.UTF16ToString(row.Description[:])
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := []model.Route{}
	for _, row := range table.Rows() {
		address, ok := windowsAddress(&row.DestinationPrefix.Prefix)
		if !ok {
			continue
		}
		prefix := netip.PrefixFrom(address, int(row.DestinationPrefix.PrefixLength))
		if !prefix.IsValid() {
			return nil, windows.ERROR_INVALID_DATA
		}
		item := model.Route{Destination: prefix.Masked().String(), InterfaceIndex: int(row.InterfaceIndex), Metric: int(row.Metric), Protocol: int(row.Protocol)}
		if gateway, ok := windowsAddress(&row.NextHop); ok {
			item.Gateway = gateway.String()
		}
		routes = append(routes, item)
	}
	return routes, nil
}
