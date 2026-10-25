package networkstate

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

func TestReadIncludesActualLoopbackInterfaceAndNativeRoutes(t *testing.T) {
	snapshot, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		found := slices.IndexFunc(snapshot.Interfaces, func(row Interface) bool {
			return row.Index == iface.Index && row.Name == iface.Name && row.Loopback && row.Up
		})
		if found < 0 {
			t.Fatal("active native loopback interface missing")
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(snapshot.Interfaces[found].Addresses, prefix.String()) {
				t.Fatal("actual loopback address missing")
			}
			if !slices.ContainsFunc(snapshot.Routes, func(row Route) bool {
				scope, err := netip.ParsePrefix(row.Destination)
				return err == nil && scope.Bits() > 1 && scope.Contains(prefix.Addr()) && row.InterfaceIndex == iface.Index
			}) {
				t.Fatal("actual loopback route missing")
			}
		}
	}
	for _, row := range snapshot.Routes {
		prefix, err := netip.ParsePrefix(row.Destination)
		if err != nil || prefix != prefix.Masked() {
			t.Fatal("invalid or broadened native destination prefix")
		}
	}
}
