package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

func TestOriginalDNSSourceValidationAndOrder(t *testing.T) {
	base := OriginalDNSRoute{Name: policy.NameRule{Kind: "suffix", Value: "original.test"}, Servers: []string{"192.0.2.53:53"}, Interface: "native-query", EgressInterface: "native-data"}
	for _, mutate := range []func(*OriginalDNSRoute){
		func(r *OriginalDNSRoute) { r.Name.Value = ".invalid" },
		func(r *OriginalDNSRoute) { r.Interface = "" },
		func(r *OriginalDNSRoute) { r.EgressInterface = "bad\x00interface" },
		func(r *OriginalDNSRoute) { r.Servers = nil },
		func(r *OriginalDNSRoute) { r.Servers = []string{"resolver.original.test:53"} },
		func(r *OriginalDNSRoute) { r.Servers = []string{"192.0.2.53:0"} },
		func(r *OriginalDNSRoute) { r.Servers = []string{"0.0.0.0:53"} },
		func(r *OriginalDNSRoute) { r.Servers = []string{"255.255.255.255:53"} },
		func(r *OriginalDNSRoute) { r.Servers = []string{"[ff02::1]:53"} },
		func(r *OriginalDNSRoute) { r.Source = "native-source"; r.Listen = "localhost:0" },
		func(r *OriginalDNSRoute) { r.Source = "native-source"; r.Listen = "0.0.0.0:0" },
		func(r *OriginalDNSRoute) { r.Source = "native-source"; r.Listen = "[::1]:0" },
		func(r *OriginalDNSRoute) { r.Source = "native-source"; r.Listen = "192.0.2.1:65536" },
		func(r *OriginalDNSRoute) { r.Listen = "192.0.2.1:0" },
	} {
		bad := base
		mutate(&bad)
		if _, err := NewOriginalDNS([]OriginalDNSRoute{bad}); err == nil {
			t.Fatal("invalid native DNS source accepted", bad)
		}
	}
	if _, err := NewOriginalDNS([]OriginalDNSRoute{base, base}); err == nil {
		t.Fatal("duplicate scope has ambiguous precedence")
	}
	exact := base
	exact.Name = policy.NameRule{Kind: "exact", Value: "private.original.test"}
	exact.Servers = []string{"[2001:db8::53]:5353", "192.0.2.54:53"}
	input := []OriginalDNSRoute{exact, base}
	compiled, err := NewOriginalDNS(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Servers[0] = "192.0.2.99:53"
	if compiled.routes[0].Name != exact.Name || !slices.Equal(compiled.routes[0].Servers, []string{"[2001:db8::53]:5353", "192.0.2.54:53"}) || compiled.routes[1].Name != base.Name {
		t.Fatal("source precedence or immutable server order changed")
	}
	base.Listen = "192.0.2.1:0"
	base.Source = "native-source"
	exact = base
	exact.Name = policy.NameRule{Kind: "exact", Value: "private.original.test"}
	if _, err := NewOriginalDNS([]OriginalDNSRoute{base, exact}); err != nil {
		t.Fatal("native scopes could not share their one listener", err)
	}
	for _, mutate := range []func(*OriginalDNSRoute){
		func(r *OriginalDNSRoute) { r.Listen = "192.0.2.2:0" },
		func(r *OriginalDNSRoute) { r.Servers = []string{"192.0.2.54:53"} },
		func(r *OriginalDNSRoute) { r.EgressInterface = "different-exit" },
	} {
		other := exact
		mutate(&other)
		if _, err := NewOriginalDNS([]OriginalDNSRoute{base, other}); err == nil {
			t.Fatal("one native listener accepted inconsistent source identity")
		}
	}
}

func originalLoopback(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	t.Fatal("no active loopback interface for original DNS")
	return ""
}

func TestOriginalDNSKeepsRecordsAndDirectionAcrossPolicyChanges(t *testing.T) {
	const host = "private.campus.test"
	iface := originalLoopback(t)
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var udpQueries, tcpQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			udpQueries.Add(1)
			if request.Question[0].Qtype == dns.TypeA {
				reply.Truncated = true
				_ = w.WriteMsg(reply)
				return
			}
		} else {
			tcpQueries.Add(1)
		}
		reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3}, Target: "target.original.test."}}
		header := dns.RR_Header{Name: "target.original.test.", Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 10}
		if request.Question[0].Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: net.IPv4(203, 0, 113, 9)})
		} else {
			reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::9")})
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Net: "tcp", Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	r := NewResolver(nil, "", "", 30, client.DomainResources{host: {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, map[string][]net.IP{host: {net.IPv4(203, 0, 113, 9)}, "localhost": {net.IPv4(203, 0, 113, 8)}}, false)
	defer r.Close()
	routes := []OriginalDNSRoute{{Name: policy.NameRule{Kind: "suffix", Value: "campus.test"}, Servers: []string{tcp.Addr().String()}, Interface: iface, EgressInterface: iface}}
	r.OriginalDNS, err = NewOriginalDNS(routes)
	if err != nil {
		t.Fatal(err)
	}
	// The caller's mutable snapshot cannot redirect an installed source.
	routes[0].Servers[0] = "127.0.0.1:1"
	var current atomic.Pointer[policy.ProtectionPolicy]
	protected, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "campus.test"}, {Kind: "suffix", Value: "localhost"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	current.Store(&protected)
	r.ProtectionPolicy = current.Load
	address := netip.MustParseAddr("203.0.113.9")
	var publications int
	publish := func(_ context.Context, addresses []netip.Addr, original bool) error {
		if !original || len(addresses) != 1 || addresses[0] != address {
			t.Fatal("wrong DNS publication direction", original, addresses)
		}
		if got, _ := r.OriginalInterfaceForIP(t.Context(), address); got != "" {
			t.Fatal("answer became usable before publication")
		}
		publications++
		return nil
	}
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply, err := r.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion(host+".", kind), "udp", nil, publish)
		if err != nil || len(reply.Answer) != 2 || reply.Answer[0].Header().Ttl != 3 || reply.Answer[1].Header().Rrtype != kind {
			t.Fatal("original records changed", reply, err)
		}
	}
	if publications != 1 || udpQueries.Load() != 2 || tcpQueries.Load() != 1 {
		t.Fatal("original UDP/TCP fallback or AAAA path missing", publications, udpQueries.Load(), tcpQueries.Load())
	}
	if got, err := r.OriginalInterfaceForIP(t.Context(), address); err != nil || got != iface {
		t.Fatal("original answer lost its exit", got, err)
	}
	if len(r.CampusResourcesForIP(t.Context(), address)) != 0 || len(r.CampusDNSRecords()) != 0 || len(r.OriginalDNSRecords()[host]) != 1 {
		t.Fatal("original answer created a campus grant or duplicate binding state")
	}
	for _, name := range []string{"localhost.", "outside.test."} {
		if _, err := r.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion(name, dns.TypeA), "udp", nil, nil); !errors.Is(err, ErrOriginalDNSRequired) {
			t.Fatal("unconfigured/local source was forwarded", name, err)
		}
	}
	if _, err := r.ExchangeCampus(t.Context(), new(dns.Msg).SetQuestion(host+".", dns.TypeA), "udp", nil, nil); !errors.Is(err, policy.ErrProtectedTarget) {
		t.Fatal("strict campus DNS used the original path", err)
	}
	chosen, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "campus.test"}}, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	current.Store(&chosen)
	if got, err := r.OriginalInterfaceForIP(t.Context(), address); got != "" || err != nil {
		t.Fatal("campus name choice kept an original binding", got, err)
	}
	reply, err := r.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion(host+".", dns.TypeA), "udp", nil, nil)
	if err != nil || len(reply.Answer) != 1 || !reply.Answer[0].(*dns.A).A.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatal("explicit campus choice did not use its granted record", reply, err)
	}
	if _, err := r.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion(host+".", dns.TypeAAAA), "udp", nil, nil); !errors.Is(err, ErrCampusIPv6Unsupported) {
		t.Fatal("campus IPv6 support was invented", err)
	}
	if len(r.CampusResourcesForIP(t.Context(), address)) != 1 {
		t.Fatal("same-IP campus choice lost its DNS authorization")
	}
	current.Store(&protected)
	if got, err := r.OriginalInterfaceForIP(t.Context(), address); err != nil || got != iface || len(r.CampusResourcesForIP(t.Context(), address)) != 0 {
		t.Fatal("same-IP campus refresh destroyed original direction on withdrawal", got, err)
	}
	if _, err := r.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion("localhost.", dns.TypeA), "udp", nil, nil); !errors.Is(err, ErrOriginalDNSRequired) {
		t.Fatal("a server-supplied localhost answer bypassed reserved local naming", err)
	}
	if udpQueries.Load() != 2 || tcpQueries.Load() != 1 {
		t.Fatal("rejected/campus questions escaped to the original server")
	}
}

func TestOriginalDNSBindingFailureExpiryAndExitConflict(t *testing.T) {
	r := NewResolver(nil, "", "", 30, nil, nil, false)
	defer r.Close()
	protected, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "original.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protected }
	address := netip.MustParseAddr("203.0.113.9")
	request := new(dns.Msg).SetQuestion("a.original.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IP(address.AsSlice())}}
	refused := errors.New("route publication refused")
	if _, err := r.bindDNSAnswer(request, reply, func([]netip.Addr) error { return refused }, "first"); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if got, _ := r.OriginalInterfaceForIP(t.Context(), address); got != "" || len(r.OriginalDNSRecords()) != 0 {
		t.Fatal("failed publication retained an original route")
	}
	if _, err := r.bindDNSAnswer(request, reply, nil, "first"); err != nil {
		t.Fatal(err)
	}
	request.Question[0].Name = "b.original.test."
	reply.Question[0] = request.Question[0]
	reply.Answer[0].Header().Name = request.Question[0].Name
	if _, err := r.bindDNSAnswer(request, reply, nil, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.OriginalInterfaceForIP(t.Context(), address); !errors.Is(err, ErrOriginalDNSConflict) {
		t.Fatal("ambiguous exit silently selected a network", err)
	}
	r.cacheMu.Lock()
	for i := range r.dnsBindings[address] {
		r.dnsBindings[address][i].expires = time.Now().Add(-time.Second)
	}
	r.cacheMu.Unlock()
	if _, err := r.OriginalInterfaceForIP(t.Context(), address); !errors.Is(err, ErrOriginalDNSConflict) || len(r.OriginalDNSRecords()) != 0 {
		t.Fatal("expired records lost their original direction protection", err)
	}
	r.Close()
	if _, err := r.OriginalInterfaceForIP(t.Context(), address); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed resolver served an original route", err)
	}
}

func TestOriginalDNSDirectionSurvivesExpiryAndCachePressure(t *testing.T) {
	r := bindingResolver()
	defer r.Close()
	protected, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "original.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protected }
	address := netip.MustParseAddr("203.0.113.9")
	request := new(dns.Msg).SetQuestion("a.original.test.", dns.TypeA)
	reply := new(dns.Msg).SetReply(request)
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IP(address.AsSlice())}}
	if _, err := r.bindDNSAnswer(request, reply, nil, "original-exit"); err != nil {
		t.Fatal(err)
	}
	r.dnsBindings[address][0].expires = time.Time{}
	// A live campus name can share this address while the old capture still exists.
	request.Question[0].Name = "live.campus.test."
	reply.Question[0] = request.Question[0]
	reply.Answer[0].Header().Name = request.Question[0].Name
	if _, err := r.bindCampusAnswer(request, reply, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.CampusResourcesForIP(t.Context(), address)) != 1 {
		t.Fatal("missing same-IP campus grant for expiry regression")
	}
	if got, err := r.OriginalInterfaceForIP(t.Context(), address); err != nil || got != "original-exit" {
		t.Fatal("TTL expiry allowed a shared-IP campus grant to win", got, err)
	}
	for _, current := range []*policy.ProtectionPolicy{nil, new(policy.ProtectionPolicy)} {
		ctx := context.WithValue(t.Context(), ContextKeyProtectionPolicy, current)
		if _, err := r.OriginalInterfaceForIP(ctx, address); !errors.Is(err, ErrOriginalDNSRequired) {
			t.Fatal("unknown name policy silently selected an exit", err)
		}
	}
	// Capacity reclamation may discard expired grants, but never direction protection.
	fill := new(dns.Msg).SetQuestion("full.original.test.", dns.TypeA)
	filled := new(dns.Msg).SetReply(fill)
	for n := 0; n < maxDNSCacheEntries-2; n++ {
		filled.Answer = append(filled.Answer, &dns.A{Hdr: dns.RR_Header{Name: fill.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(198, 19, byte(n>>8), byte(n))})
	}
	if _, err := r.bindDNSAnswer(fill, filled, nil, "original-exit"); err != nil {
		t.Fatal(err)
	}
	for ip, bindings := range r.dnsBindings {
		for n := range bindings {
			if bindings[n].originalInterface != "" {
				bindings[n].expires = time.Time{}
			}
		}
		r.dnsBindings[ip] = bindings
	}
	request.Question[0].Name = "next.campus.test."
	reply.Question[0] = request.Question[0]
	reply.Answer[0].Header().Name = request.Question[0].Name
	if _, err := r.bindCampusAnswer(request, reply, nil); !errors.Is(err, ErrCampusDNSCapacity) {
		t.Fatal("capacity pressure evicted original direction protection", err)
	}
	if got, err := r.OriginalInterfaceForIP(t.Context(), address); err != nil || got != "original-exit" {
		t.Fatal("cache reclamation changed original direction", got, err)
	}
}
