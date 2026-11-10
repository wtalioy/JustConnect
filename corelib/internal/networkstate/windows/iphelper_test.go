//go:build windows

package networkstate

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/windows"
)

func fixtureAdapters() *windows.IpAdapterAddresses {
	name, _ := windows.UTF16PtrFromString("loopback fixture")
	description, _ := windows.UTF16PtrFromString("native description")
	second, _ := windows.UTF16PtrFromString("IPv6 only fixture")
	v4, v6 := &syscall.RawSockaddrAny{}, &syscall.RawSockaddrAny{}
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(v4)) = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
	*(*windows.RawSockaddrInet6)(unsafe.Pointer(v6)) = windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}}
	addresses := &windows.IpAdapterUnicastAddress{OnLinkPrefixLength: 64, Address: windows.SocketAddress{Sockaddr: v6, SockaddrLength: int32(unsafe.Sizeof(windows.RawSockaddrInet6{}))}, Next: &windows.IpAdapterUnicastAddress{OnLinkPrefixLength: 8, Address: windows.SocketAddress{Sockaddr: v4, SockaddrLength: int32(unsafe.Sizeof(windows.RawSockaddrInet4{}))}}}
	return &windows.IpAdapterAddresses{IfIndex: 7, FriendlyName: name, Description: description, OperStatus: windows.IfOperStatusUp, IfType: windows.IF_TYPE_SOFTWARE_LOOPBACK, FirstUnicastAddress: addresses, Next: &windows.IpAdapterAddresses{Ipv6IfIndex: 91, FriendlyName: second}}
}

func TestInterfaceFactsPreserveAddressesMetadataAndIPv6OnlyIndex(t *testing.T) {
	got, err := interfaceFacts(fixtureAdapters())
	want := []model.Interface{{Index: 7, Name: "loopback fixture", Description: "native description", Up: true, Loopback: true, Addresses: []string{"127.0.0.1/8", "fd00::9/64"}}, {Index: 91, Name: "IPv6 only fixture", Addresses: []string{}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("native interface facts changed: %v, %v", got, err)
	}
}

func TestInterfaceFactsRejectIncompleteIdentityAndInvalidAddresses(t *testing.T) {
	for _, change := range []string{"missing_index", "invalid_family", "invalid_prefix"} {
		t.Run(change, func(t *testing.T) {
			adapters := fixtureAdapters()
			switch change {
			case "missing_index":
				adapters.Next.Ipv6IfIndex = 0
			case "invalid_family":
				adapters.FirstUnicastAddress.Address.Sockaddr.Addr.Family = windows.AF_UNSPEC
			case "invalid_prefix":
				adapters.FirstUnicastAddress.OnLinkPrefixLength = 129
			}
			got, err := interfaceFacts(adapters)
			if got != nil || !errors.Is(err, windows.ERROR_INVALID_DATA) {
				t.Fatalf("incomplete native facts published: %v, %v", got, err)
			}
		})
	}
}

func systemInterfaces() ([]model.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []model.Interface{}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		item := model.Interface{Index: iface.Index, Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, err
			}
			item.Addresses = append(item.Addresses, prefix.String())
		}
		slices.Sort(item.Addresses)
		result = append(result, item)
	}
	return result, nil
}

func TestReadInterfacesMatchesSystemInterfaces(t *testing.T) {
	got, err := ReadInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	want, err := systemInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		row := windows.MibIfRow2{InterfaceIndex: uint32(got[i].Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
			t.Fatal(err)
		}
		if got[i].Description != windows.UTF16ToString(row.Description[:]) {
			t.Fatal("native interface description changed")
		}
		got[i].Description = ""
	}
	slices.SortFunc(got, func(a, b model.Interface) int { return a.Index - b.Index })
	slices.SortFunc(want, func(a, b model.Interface) int { return a.Index - b.Index })
	if !reflect.DeepEqual(got, want) {
		t.Fatal("interface facts differ from system enumeration")
	}
}

func TestDefaultIPv4ExitUsesCombinedMetricAndRejectsVirtualRoutes(t *testing.T) {
	rows := []windows.MibIpForwardRow2{
		{InterfaceLuid: 1, Metric: 1},
		{InterfaceLuid: 2, Metric: 1},
		{InterfaceLuid: 3, Metric: 1},
		{InterfaceLuid: 4, Metric: 1},
		{InterfaceLuid: 5, Metric: 1},
		{InterfaceLuid: 6, Metric: 10},
		{InterfaceLuid: 7, Metric: 15},
		{InterfaceLuid: 8, Metric: ^uint32(0)},
	}
	rows[0].DestinationPrefix.PrefixLength = 24
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&rows[1].NextHop)) =
		windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{25, 255, 255, 254}}
	names := []string{"subnet", "synthetic", "down", "virtual", "loopback", "ordinary", "higher priority", "overflow"}
	readInterface := func(luid uint64) (windows.MibIfRow2, error) {
		alias, err := windows.UTF16FromString(names[luid-1])
		iface := windows.MibIfRow2{OperStatus: windows.IfOperStatusUp}
		copy(iface.Alias[:], alias)
		switch luid {
		case 3:
			iface.OperStatus = windows.IfOperStatusDown
		case 4:
			iface.Type = 53 // IF_TYPE_PROP_VIRTUAL.
		case 5:
			iface.Type = windows.IF_TYPE_SOFTWARE_LOOPBACK
		}
		return iface, err
	}
	readMetric := func(luid uint64) (uint32, error) {
		if luid == 6 {
			return 20, nil
		}
		return 1, nil
	}
	if got := selectDefaultIPv4Interface(rows, readInterface, readMetric); got != "higher priority" {
		t.Fatalf("default IPv4 exit = %q, want combined-metric winner", got)
	}
}

func BenchmarkInterfaces(b *testing.B) {
	for _, tc := range []struct {
		name string
		read func() ([]model.Interface, error)
	}{{"system", systemInterfaces}, {"native", ReadInterfaces}} {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := tc.read(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReadRoutes(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ReadRoutes(); err != nil {
			b.Fatal(err)
		}
	}
}
