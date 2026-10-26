package bridge

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestProtocolOwnsOriginalDNSListeners(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			loopback = iface.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("no active original loopback interface")
	}
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: upstream, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(203, 0, 113, 9)}}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	g := newGateway(t)
	e := New(RunProtocol)
	h := create(t, e)
	config := g.config(t)
	config.Protection = &ProtectionConfig{Protected: []string{}, Campus: []string{}, ProtectedNames: []policy.NameRule{{Kind: "suffix", Value: "original.test"}}}
	config.Network.OriginalDNS = []resolve.OriginalDNSRoute{{Name: config.Protection.ProtectedNames[0],
		Servers: []string{upstream.LocalAddr().String()}, Interface: loopback, EgressInterface: loopback, Source: loopback, Listen: "127.0.0.1:0"}}
	var oldGeneration uint64
	for round := 0; round < 2; round++ {
		startProtocol(t, e, h, config)
		ready := next(t, e, h)
		if ready.State != "ready" {
			t.Fatal(ready)
		}
		readResources := func() resourceSnapshot {
			data, status := e.Resources(h, ready.Generation)
			var value resourcesEnvelope
			if status != OK || json.Unmarshal(data, &value) != nil || value.Generation != ready.Generation {
				t.Fatal("invalid generation-bound original DNS resources", status)
			}
			return value.Resources
		}
		address := readResources().OriginalDNSListeners[loopback]
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil || endpoint.Port() == 0 || !endpoint.Addr().IsLoopback() {
			t.Fatal("session did not publish its actual prepared DNS endpoint", address, err)
		}
		exerciseProtocolTUN(t, e, h, ready.Generation)
		reply, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion("host.original.test.", dns.TypeA), address)
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
			t.Fatal("actual protocol session did not forward through original DNS", reply, err)
		}
		resources := readResources()
		if len(resources.OriginalDNSRecords["host.original.test"]) != 1 || resources.OriginalDNSRecords["host.original.test"][0] != "203.0.113.9" || len(resources.DNSRecords["host.original.test"]) != 0 {
			t.Fatal("original listener records leaked into campus DNS grants")
		}
		if oldGeneration != 0 {
			if _, status := e.Resources(h, oldGeneration); status != StaleRequest {
				t.Fatal("old generation retained DNS listener authority", status)
			}
		}
		if e.Stop(h, 3000) != OK {
			t.Fatal("stop did not join original DNS listeners")
		}
		if event := next(t, e, h); event.Type != "terminal" || event.Status != Cancelled {
			t.Fatal(event)
		}
		if _, status := e.Resources(h, ready.Generation); status != StaleRequest {
			t.Fatal("stopped session exposed native DNS endpoint", status)
		}
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal("protocol stop retained original DNS TCP socket", err)
		}
		tcp.Close()
		udp, err := net.ListenPacket("udp4", address)
		if err != nil {
			t.Fatal("protocol stop retained original DNS UDP socket", err)
		}
		udp.Close()
		oldGeneration = ready.Generation
	}
}
