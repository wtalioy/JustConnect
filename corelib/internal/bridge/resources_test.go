package bridge

import (
	"context"
	"encoding/json"
	"net"
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
