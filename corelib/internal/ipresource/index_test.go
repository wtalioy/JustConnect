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
		{IPMin: net.ParseIP("10.8.0.0"), IPMax: net.ParseIP("198.51.100.33"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
		{IPMin: net.ParseIP("1.0.0.0"), IPMax: net.ParseIP("10.6.255.255"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
		{IPMin: net.ParseIP("198.51.100.41"), IPMax: net.ParseIP("255.255.255.255"), AppID: "default", Protocol: "all", PortMin: 1, PortMax: 65535},
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
	lastStart := ranges[3].IPMin
	ranges[3].IPMin = net.ParseIP("198.51.101.41")
	if scoped, private := ScopedRanges(ranges); len(scoped) != len(ranges) || len(private) != 0 {
		t.Fatal("a public subnet outside the grant was mistaken for a host exemption", scoped, private)
	}
	ranges[3].IPMin = lastStart
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

func TestIndexKeepsRangeAcrossSubtrees(t *testing.T) {
	start := net.IPv4(192, 0, 2, 0)
	end := net.IPv4(192, 0, 2, 255)
	resources := []client.IPResource{
		{IPMin: end, IPMax: start, Protocol: "all", PortMin: 1, PortMax: 65535},
		{IPMin: start, IPMax: end, Protocol: "all", PortMin: 443, PortMax: 443, AppID: "range"},
	}
	for _, last := range []byte{180, 20, 150, 90} {
		ip := net.IPv4(192, 0, 2, last)
		resources = append(resources, client.IPResource{IPMin: ip, IPMax: ip, Protocol: "tcp", PortMin: 443, PortMax: 443})
	}
	index := New(resources)
	if got, ok := index.Match(end, "tcp", 443); !ok || got.AppID != "range" {
		t.Fatalf("range ending past the midpoint was lost: %v, %t", got, ok)
	}
	if _, ok := index.Match(end, "tcp", 80); ok {
		t.Fatal("match ignored the port bound or accepted the reversed range")
	}
}

func BenchmarkIndex(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", resourceCount), func(b *testing.B) {
			resources := make([]client.IPResource, resourceCount)
			for i := range resources {
				ip := net.IPv4(10, byte(i>>8), byte(i), 1)
				resources[i] = client.IPResource{IPMin: ip, IPMax: ip, PortMin: 443, PortMax: 443, Protocol: "tcp"}
			}
			target := resources[len(resources)-1].IPMin
			b.Run("build", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, ok := New(resources).Match(target, "tcp", 443); !ok {
						b.Fatal("target did not match")
					}
				}
			})
			b.Run("match", func(b *testing.B) {
				index := New(resources)
				b.ReportAllocs()
				for b.Loop() {
					if _, ok := index.Match(target, "tcp", 443); !ok {
						b.Fatal("target did not match")
					}
				}
			})
		})
	}
}
