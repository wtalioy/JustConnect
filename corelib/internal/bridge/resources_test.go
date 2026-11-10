package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/client"
)

func TestResourcesAreOwnedBoundedAndScopedToTheActiveGeneration(t *testing.T) {
	entered := make(chan *Session, 2)
	e := New(func(ctx context.Context, _ Config, s *Session) Status { entered <- s; <-ctx.Done(); return Cancelled })
	h := create(t, e)
	g, status := e.Start(h, []byte(configJSON))
	if status != OK {
		t.Fatal(status)
	}
	s := <-entered
	if _, status := e.Resources(h, g); status != Busy {
		t.Fatal(status)
	}
	ip := net.IPv4(192, 0, 2, 10)
	resources := corelib.Resources{IPs: []client.IPResource{{IPMin: ip, IPMax: ip, Protocol: "tcp", PortMin: 22, PortMax: 22, AppID: "private-app", NodeGroupID: "private-node"}}, Domains: client.DomainResources{".campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}, DNSRecords: map[string][]net.IP{"ssh.campus.test": {ip}}, CampusDNS: "192.0.2.53", CampusDNSEnabled: true, UnderlayInterface: "original0"}
	if status := s.setResources(resources); status != OK {
		t.Fatal(status)
	}
	ip[15] = 11
	resources.Domains[".campus.test"][0].PortMax = 80
	data, status := e.Resources(h, g)
	if status != OK || strings.Contains(string(data), "private-") {
		t.Fatal("unavailable or overexposed resource snapshot", status)
	}
	var result struct {
		Generation string           `json:"generation"`
		Resources  resourceSnapshot `json:"resources"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Generation != "1" || len(result.Resources.IPs) != 1 || result.Resources.IPs[0].IPMin != "192.0.2.10" || result.Resources.IPs[0].PortMin != 22 || result.Resources.Domains[".campus.test"][0].PortMax != 443 || result.Resources.DNSRecords["ssh.campus.test"][0] != "192.0.2.10" || !result.Resources.CampusDNSEnabled || result.Resources.UnderlayInterface != "original0" {
		t.Fatal("parsed permissions or borrowed input changed")
	}
	clear(data)
	if data, status := e.Resources(h, g); status != OK || !json.Valid(data) {
		t.Fatal("caller modified stored resource bytes", status)
	}
	if _, status := e.Resources(h, g+1); status != StaleRequest {
		t.Fatal(status)
	}
	if _, status := e.Resources(h, 0); status != InvalidArgument {
		t.Fatal(status)
	}
	if _, status := e.Resources(h+100, g); status != InvalidHandle {
		t.Fatal(status)
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop")
	}
	if _, status := e.Resources(h, g); status != StaleRequest {
		t.Fatal(status)
	}
	read(t, e, h)
	read(t, e, h)
	g2, status := e.Start(h, []byte(configJSON))
	if status != OK {
		t.Fatal(status)
	}
	<-entered
	if _, status := e.Resources(h, g); status != StaleRequest {
		t.Fatal(status)
	}
	if _, status := e.Resources(h, g2); status != Busy {
		t.Fatal("previous session resources leaked", status)
	}
	if status := s.setResources(corelib.Resources{DNSRecords: map[string][]net.IP{strings.Repeat("large", MaxOutput): {ip}}}); status != Limit {
		t.Fatal(status)
	}
	if data, status := e.Resources(h, g2); status != Limit || len(data) != 0 {
		t.Fatal("oversized snapshot was truncated or exposed", status)
	}
}

func TestResourceSnapshotWithdrawsLiveDataAndRetainsOwnedRules(t *testing.T) {
	s := &Session{running: true, generation: 1}
	const host = "campus.test"
	baseIP := net.IPv4(192, 0, 2, 1)
	baseRange := [2]netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")}
	ranges := [][2]netip.Addr{baseRange}
	names := []string{host}
	if status := s.setResources(corelib.Resources{
		DNSRecords: map[string][]net.IP{host: {baseIP}}, DomainDNSNames: names, PrivateIPRanges: ranges,
	}); status != OK {
		t.Fatal(status)
	}
	names[0] = "changed.test"
	ranges[0] = [2]netip.Addr{}
	read := func(activity resourceActivity) resourceSnapshot {
		t.Helper()
		data, status := s.resources.snapshot(activity)
		var envelope resourcesEnvelope
		if status != OK || json.Unmarshal(data, &envelope) != nil || envelope.Generation != 1 {
			t.Fatalf("invalid resource snapshot: %v", status)
		}
		clear(data)
		return envelope.Resources
	}

	live := resourceActivity{
		active:    []string{"192.0.2.2"},
		campus:    map[string][]string{host: {"192.0.2.2", "192.0.2.1"}},
		original:  map[string][]string{"original.test": {"192.0.2.3"}},
		listeners: map[string]string{"link": "127.0.0.1:12345"},
	}
	for range 2 {
		view := read(live)
		if !slices.Equal(view.DNSRecords[host], []string{"192.0.2.1", "192.0.2.2"}) ||
			!slices.Equal(view.ActiveTUNAddresses, live.active) ||
			!slices.Equal(view.OriginalDNSRecords["original.test"], live.original["original.test"]) ||
			view.OriginalDNSListeners["link"] != live.listeners["link"] {
			t.Fatalf("live state lost or duplicated: %+v", view)
		}
	}
	tooLarge := resourceActivity{original: map[string][]string{strings.Repeat("x", MaxOutput): {"192.0.2.3"}}}
	if data, status := s.resources.snapshot(tooLarge); status != Limit || len(data) != 0 {
		t.Fatal("oversized live resource snapshot was exposed", status)
	}
	view := read(resourceActivity{})
	if !slices.Equal(view.DNSRecords[host], []string{"192.0.2.1"}) ||
		!slices.Equal(view.DomainDNSNames, []string{host}) ||
		!slices.Equal(view.PrivateIPRanges, [][2]netip.Addr{baseRange}) ||
		len(view.ActiveTUNAddresses)+len(view.OriginalDNSRecords)+len(view.OriginalDNSListeners) != 0 {
		t.Fatalf("live withdrawal changed published rules or kept stale data: %+v", view)
	}
}

func benchmarkResourceFixture() corelib.Resources {
	ip := net.IPv4(192, 0, 2, 10)
	resources := corelib.Resources{Domains: make(client.DomainResources), DNSRecords: make(map[string][]net.IP)}
	for i := range 256 {
		resources.IPs = append(resources.IPs, client.IPResource{IPMin: ip, IPMax: ip, Protocol: "tcp", PortMin: 22, PortMax: 22})
		name := fmt.Sprintf("service-%d.campus.test", i)
		resources.Domains[name] = []client.DomainResource{{Protocol: "tcp", PortMin: 22, PortMax: 22}, {Protocol: "tcp", PortMin: 443, PortMax: 443}}
		resources.DNSRecords[name] = []net.IP{ip}
	}
	return resources
}

func BenchmarkPublishResourceSnapshot(b *testing.B) {
	s := &Session{running: true, generation: 1}
	resources := benchmarkResourceFixture()
	b.ReportAllocs()
	for b.Loop() {
		if status := s.setResources(resources); status != OK {
			b.Fatal(status)
		}
	}
}

func BenchmarkRefreshResourceSnapshot(b *testing.B) {
	for _, stable := range []bool{true, false} {
		b.Run(fmt.Sprintf("stable=%t", stable), func(b *testing.B) {
			s := &Session{running: true, generation: 1}
			if status := s.setResources(benchmarkResourceFixture()); status != OK {
				b.Fatal(status)
			}
			active := []string{"192.0.2.20"}
			records := map[string][]string{"service-0.campus.test": {"192.0.2.99"}}
			original := map[string][]string{"original.test": {"192.0.2.80"}}
			listeners := map[string]string{"source": "127.0.0.1:12345"}
			b.ReportAllocs()
			for b.Loop() {
				if !stable {
					if active[0] == "192.0.2.20" {
						active = []string{"192.0.2.21"}
					} else {
						active = []string{"192.0.2.20"}
					}
				}
				data, status := s.resources.snapshot(resourceActivity{active, records, original, listeners})
				if status != OK || len(data) == 0 {
					b.Fatal(status)
				}
			}
		})
	}
}
