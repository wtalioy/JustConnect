package wintun

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var initializeAddress = ipHelper.NewProc("InitializeUnicastIpAddressEntry")
var createAddress = ipHelper.NewProc("CreateUnicastIpAddressEntry")
var setInterface = ipHelper.NewProc("SetIpInterfaceEntry")
var initializeRoute = ipHelper.NewProc("InitializeIpForwardEntry")
var createRoute = ipHelper.NewProc("CreateIpForwardEntry2")

func ipv4(address netip.Addr) windows.RawSockaddrInet {
	var result windows.RawSockaddrInet
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&result)) = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: address.As4()}
	return result
}

func (d *Device) configure(source, peer netip.Addr, targets []netip.Prefix) error {
	iface := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: d.LUID}
	if err := windows.GetIpInterfaceEntry(&iface); err != nil {
		return fmt.Errorf("read owned IPv4 interface: %w", err)
	}
	// SetIpInterfaceEntry requires zero for IPv4, even if the readback differs.
	iface.SitePrefixLength = 0
	iface.UseAutomaticMetric, iface.Metric, iface.NlMtu, iface.DadTransmits, iface.DisableDefaultRoutes = 0, 1, d.mtu, 0, 1
	if status, _, _ := setInterface.Call(uintptr(unsafe.Pointer(&iface))); status != 0 {
		return fmt.Errorf("configure owned IPv4 interface: %w", windows.Errno(status))
	}
	confirmedInterface := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: d.LUID}
	if err := windows.GetIpInterfaceEntry(&confirmedInterface); err != nil {
		return fmt.Errorf("confirm owned IPv4 interface: %w", err)
	}
	if confirmedInterface.NlMtu != d.mtu || confirmedInterface.UseAutomaticMetric != 0 || confirmedInterface.Metric != iface.Metric || confirmedInterface.DadTransmits != 0 || confirmedInterface.DisableDefaultRoutes != 1 {
		return fmt.Errorf("owned IPv4 interface differs: MTU=%d/%d automatic_metric=%d metric=%d/%d DAD=%d disable_default=%d: %w", confirmedInterface.NlMtu, d.mtu, confirmedInterface.UseAutomaticMetric, confirmedInterface.Metric, iface.Metric, confirmedInterface.DadTransmits, confirmedInterface.DisableDefaultRoutes, windows.ERROR_INVALID_DATA)
	}
	var row windows.MibUnicastIpAddressRow
	initializeAddress.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = d.LUID
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address)) = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: source.As4()}
	row.OnLinkPrefixLength, row.DadState = 32, windows.IpDadStatePreferred
	if status, _, _ := createAddress.Call(uintptr(unsafe.Pointer(&row))); status != 0 {
		return fmt.Errorf("create owned IPv4 address: %w", windows.Errno(status))
	}
	confirmed := row
	if err := windows.GetUnicastIpAddressEntry(&confirmed); err != nil {
		return fmt.Errorf("confirm owned IPv4 address: %w", err)
	}
	if confirmed.InterfaceLuid != d.LUID || confirmed.OnLinkPrefixLength != 32 || confirmed.DadState != windows.IpDadStatePreferred {
		return fmt.Errorf("owned IPv4 address differs: LUID=%d/%d prefix=%d DAD=%d: %w", confirmed.InterfaceLuid, d.LUID, confirmed.OnLinkPrefixLength, confirmed.DadState, windows.ERROR_INVALID_DATA)
	}
	// Only routes on this newly allocated adapter are touched; its last owner removes them.
	all := append([]netip.Prefix{netip.PrefixFrom(peer, 32)}, targets...)
	seen := make(map[netip.Prefix]bool)
	for _, prefix := range all {
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		var route windows.MibIpForwardRow2
		initializeRoute.Call(uintptr(unsafe.Pointer(&route)))
		route.InterfaceLuid = d.LUID
		route.DestinationPrefix = windows.IpAddressPrefix{Prefix: ipv4(prefix.Addr()), PrefixLength: uint8(prefix.Bits())}
		route.NextHop, route.Metric, route.Protocol = ipv4(netip.IPv4Unspecified()), 1, windows.MIB_IPPROTO_NETMGMT
		if status, _, _ := createRoute.Call(uintptr(unsafe.Pointer(&route))); status != 0 {
			return fmt.Errorf("create owned IPv4 capture: %w", windows.Errno(status))
		}
		confirmed := route
		if err := windows.GetIpForwardEntry2(&confirmed); err != nil {
			return fmt.Errorf("confirm owned IPv4 capture: %w", err)
		}
		if confirmed.InterfaceLuid != d.LUID || confirmed.Metric != route.Metric || confirmed.Protocol != route.Protocol {
			return fmt.Errorf("owned IPv4 capture differs: LUID=%d/%d metric=%d/%d protocol=%d/%d: %w", confirmed.InterfaceLuid, d.LUID, confirmed.Metric, route.Metric, confirmed.Protocol, route.Protocol, windows.ERROR_INVALID_DATA)
		}
	}
	return nil
}
