package service

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

// Uses an explicitly supplied live native source; the packet device stays in memory.
func TestNativeProtectedOriginalDNS(t *testing.T) {
	input := os.Getenv("JC_NATIVE_ORIGINAL_DNS_CONFIG")
	if input == "" {
		t.Skip("provide a live native resolver snapshot for this read-only integration")
	}
	var config struct {
		Route     resolve.OriginalDNSRoute `json:"route"`
		Name      string                   `json:"name"`
		Addresses []string                 `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSuffix(config.Name, ".")
	if !config.Route.Name.Matches(host) || config.Route.Listen != "127.0.0.1:0" {
		t.Fatal("native query must belong to the supplied source and a private loopback listener")
	}
	expected := make(map[netip.Addr]bool)
	for _, address := range config.Addresses {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			t.Fatal(err)
		}
		expected[ip.Unmap()] = true
	}
	r := resolve.NewResolver(nil, "", "", 30,
		client.DomainResources{host: {{Protocol: "tcp", PortMin: 443, PortMax: 443}}},
		map[string][]net.IP{host: {net.IPv4(198, 19, 0, 123)}}, false)
	t.Cleanup(r.Close)
	protection, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{config.Route.Name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protection }
	r.OriginalDNS, err = resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{config.Route})
	if err != nil {
		t.Fatal(err)
	}
	d := dial.NewDialer(nil, r, nil, false)
	d.ProtectionPolicy = r.ProtectionPolicy
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var publications atomic.Int32
	if err := p.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, func(_ context.Context, addresses []netip.Addr, exclude bool) error {
		if !exclude {
			t.Error("protected native answer became a campus capture")
		}
		for _, address := range addresses {
			if !expected[address.Unmap()] {
				t.Error("publication did not match the actual native node")
			}
		}
		publications.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"udp", "tcp"} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			question := new(dns.Msg).SetQuestion(dns.Fqdn(host), qtype)
			baseline, _, err := (&dns.Client{Net: transport, Timeout: 5 * time.Second}).ExchangeContext(t.Context(),
				question, config.Route.Servers[0])
			if err != nil || baseline.Rcode != dns.RcodeSuccess || (qtype == dns.TypeA && len(baseline.Answer) == 0) {
				t.Fatal("actual native upstream baseline", transport, qtype, err)
			}
			reply, _, err := (&dns.Client{Net: transport, Timeout: 5 * time.Second}).ExchangeContext(t.Context(),
				question, p.OriginalDNSListeners()[config.Route.Source])
			if err != nil {
				t.Fatal("actual native source listener exchange", transport, qtype, err)
			}
			if reply.Rcode != baseline.Rcode || len(reply.Answer) != len(baseline.Answer) {
				t.Fatal("actual native source reply", transport, qtype, "rcode", reply.Rcode, "answers", len(reply.Answer))
			}
			for _, answer := range reply.Answer {
				var ip net.IP
				switch record := answer.(type) {
				case *dns.A:
					ip = record.A
				case *dns.AAAA:
					ip = record.AAAA
				default:
					t.Fatal("unexpected native node answer type")
				}
				address, ok := netip.AddrFromSlice(ip)
				if !ok || !expected[address.Unmap()] {
					t.Fatal("native answer escaped its source or used the overlapping campus mapping")
				}
			}
			t.Log("native DNS answer preserved", transport, qtype, "records", len(reply.Answer))
		}
	}
	if publications.Load() == 0 {
		t.Fatal("protected answers escaped before any original-direction publication")
	}
	t.Log("PASS: actual protected native A/AAAA over UDP/TCP through core listeners; overlapping campus mapping excluded; no system network changes")
}
