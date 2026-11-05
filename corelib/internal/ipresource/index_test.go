package ipresource

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
)

func TestScopedRangesPreservePrivateHolesAndNarrowGrants(t *testing.T) {
	ranges := []client.IPResource{
		{IPMin: net.ParseIP("10.7.0.1"), IPMax: net.ParseIP("10.7.0.1"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
		{IPMin: net.ParseIP("10.8.0.0"), IPMax: net.ParseIP("255.255.255.255"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
		{IPMin: net.ParseIP("0.0.0.0"), IPMax: net.ParseIP("10.6.255.255"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
	}
	scoped, private := ScopedRanges(ranges)
	if len(scoped) != 1 || !scoped[0].IPMin.Equal(ranges[0].IPMin) {
		t.Fatal("the private hole lost its explicit campus resource", scoped)
	}
	expected := [][2]netip.Addr{
		{netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.6.255.255")},
		{netip.MustParseAddr("10.8.0.0"), netip.MustParseAddr("10.255.255.255")},
		{netip.MustParseAddr("172.16.0.0"), netip.MustParseAddr("172.31.255.255")},
		{netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("192.168.255.255")},
	}
	if !slices.Equal(private, expected) {
		t.Fatal("private capture widened the grant or lost destinations", private)
	}
	ranges[2].PortMax = 443
	if scoped, private := ScopedRanges(ranges); len(scoped) != len(ranges) || len(private) != 0 {
		t.Fatal("independent authorizations were mistaken for one complete grant", scoped, private)
	}
}

func TestIndexPreservesFirstMatchingResource(t *testing.T) {
	index := New([]client.IPResource{
		{IPMin: net.IPv4(10, 0, 0, 0), IPMax: net.IPv4(10, 0, 0, 255), PortMin: 1, PortMax: 65535, Protocol: "all", AppID: "first"},
		{IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "more-specific"},
	})
	resource, ok := index.Match(net.IPv4(10, 0, 0, 42), "tcp", 443)
	if !ok {
		t.Fatal("overlapping resource did not match")
	}
	if resource.AppID != "first" {
		t.Fatalf("matched AppID = %q, want first rule", resource.AppID)
	}
}

func TestIndexCanPreserveLastMatchingResource(t *testing.T) {
	index := New([]client.IPResource{
		{IPMin: net.IPv4(10, 0, 0, 0), IPMax: net.IPv4(10, 0, 0, 255), PortMin: 1, PortMax: 65535, Protocol: "all", AppID: "first"},
		{IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "last"},
	})
	resource, ok := index.MatchLastWhere(net.IPv4(10, 0, 0, 42), "tcp", 443, nil)
	if !ok {
		t.Fatal("overlapping resource did not match")
	}
	if resource.AppID != "last" {
		t.Fatalf("matched AppID = %q, want last rule", resource.AppID)
	}
}

func TestIndexCanFilterMatchingResources(t *testing.T) {
	index := New([]client.IPResource{
		{IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "tcp-tunnel"},
		{IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "l3", EnableTCPPrefL3: true},
	})
	resource, ok := index.MatchLastWhere(net.IPv4(10, 0, 0, 42), "tcp", 443, func(resource client.IPResource) bool {
		return !resource.EnableTCPPrefL3
	})
	if !ok || resource.AppID != "tcp-tunnel" {
		t.Fatalf("filtered match = (%#v, %t), want tcp-tunnel", resource, ok)
	}
}

func TestNilIndexDoesNotMatch(t *testing.T) {
	var index *Index
	if _, ok := index.Match(net.IPv4(10, 0, 0, 1), "tcp", 443); ok {
		t.Fatal("nil index unexpectedly matched a resource")
	}
}

func BenchmarkIndexMatch(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", resourceCount), func(b *testing.B) {
			resources := make([]client.IPResource, resourceCount)
			for i := range resources {
				ip := net.IPv4(10, byte(i>>8), byte(i), 1)
				resources[i] = client.IPResource{IPMin: ip, IPMax: ip, PortMin: 443, PortMax: 443, Protocol: "tcp"}
			}
			index := New(resources)
			target := resources[len(resources)-1].IPMin
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := index.Match(target, "tcp", 443); !ok {
					b.Fatal("target did not match")
				}
			}
		})
	}
}
