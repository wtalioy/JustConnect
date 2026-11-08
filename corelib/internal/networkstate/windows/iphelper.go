//go:build windows

package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net/netip"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsAddress(value *windows.RawSockaddrInet) (netip.Addr, bool) {
	address := windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(value)), SockaddrLength: int32(unsafe.Sizeof(*value))}
	ip, ok := netip.AddrFromSlice(address.IP())
	return ip, ok
}

// DefaultIPv4Interface selects the usable default route by combined route and interface metric.
func DefaultIPv4Interface() string {
	var table *windows.MibIpForwardTable2
	if windows.GetIpForwardTable2(windows.AF_INET, &table) != nil {
		return ""
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return selectDefaultIPv4Interface(table.Rows(), func(luid uint64) (windows.MibIfRow2, error) {
		iface := windows.MibIfRow2{InterfaceLuid: luid}
		err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &iface)
		return iface, err
	}, func(luid uint64) (uint32, error) {
		ip := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
		err := windows.GetIpInterfaceEntry(&ip)
		return ip.Metric, err
	})
}

func selectDefaultIPv4Interface(routes []windows.MibIpForwardRow2,
	readInterface func(uint64) (windows.MibIfRow2, error), readMetric func(uint64) (uint32, error)) string {
	const propVirtualInterface = 53 // IF_TYPE_PROP_VIRTUAL in ipifcons.h.
	zeroTierGateway := netip.AddrFrom4([4]byte{25, 255, 255, 254})
	bestMetric := uint64(^uint32(0))
	name := ""
	for _, row := range routes {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		// ZeroTier's synthetic gateway is not an ordinary default exit.
		if gateway, _ := windowsAddress(&row.NextHop); gateway == zeroTierGateway {
			continue
		}
		iface, err := readInterface(row.InterfaceLuid)
		if err != nil || iface.OperStatus != windows.IfOperStatusUp ||
			iface.Type == propVirtualInterface || iface.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		interfaceMetric, err := readMetric(row.InterfaceLuid)
		if err != nil {
			continue
		}
		metric := uint64(row.Metric) + uint64(interfaceMetric)
		if metric < bestMetric {
			bestMetric = metric
			name = windows.UTF16ToString(iface.Alias[:])
		}
	}
	return name
}

func ReadRoutes(_ []model.Interface) ([]model.Route, error) {
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

// GAA_FLAG_SKIP_DNS_INFO (also used by WireGuard winipcfg) omits DNS suffix metadata.
// x/sys omits this flag; SKIP_DNS_SERVER alone still queries DNS Client metadata.
const skipDNSInfo = 0x0800

// ReadInterfaces collects addresses and metadata in one query without DNS Client RPCs.
func ReadInterfaces() ([]model.Interface, error) {
	size := uint32(15000) // Microsoft's recommended initial GetAdaptersAddresses buffer.
	for {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER | skipDNSInfo
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW && size > uint32(len(buffer)) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return []model.Interface{}, nil
		}
		return interfaceFacts(first)
	}
}

func interfaceFacts(first *windows.IpAdapterAddresses) ([]model.Interface, error) {
	result := []model.Interface{}
	for row := first; row != nil; row = row.Next {
		index := row.IfIndex
		if index == 0 {
			index = row.Ipv6IfIndex
		}
		if index == 0 {
			return nil, windows.ERROR_INVALID_DATA
		}
		item := model.Interface{Index: int(index), Name: windows.UTF16PtrToString(row.FriendlyName), Description: windows.UTF16PtrToString(row.Description), Up: row.OperStatus == windows.IfOperStatusUp, Loopback: row.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK, Addresses: []string{}}
		for address := row.FirstUnicastAddress; address != nil; address = address.Next {
			ip, ok := netip.AddrFromSlice(address.Address.IP())
			if !ok {
				return nil, windows.ERROR_INVALID_DATA
			}
			prefix := netip.PrefixFrom(ip, int(address.OnLinkPrefixLength))
			if !prefix.IsValid() {
				return nil, windows.ERROR_INVALID_DATA
			}
			item.Addresses = append(item.Addresses, prefix.String())
		}
		slices.Sort(item.Addresses)
		result = append(result, item)
	}
	return result, nil
}
