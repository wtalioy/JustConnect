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
