package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

func TestProtectedCampusDNSCannotReachTunnelOrPublicResolver(t *testing.T) {
	snapshot, err := policy.NewProtectionPolicy([]string{"192.0.2.0/24"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nil, "192.0.2.53", "", 60, client.DomainResources{".campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}, nil, true)
	defer r.Close()
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &snapshot }
	for _, resolver := range []*net.Resolver{r.remoteUDPResolver, r.remoteTCPResolver} {
		if _, err := resolver.Dial(t.Context(), "udp", "unused"); !errors.Is(err, policy.ErrProtectedTarget) {
			t.Fatal(err)
		}
	}
	var public atomic.Int32
	r.secondaryResolver.Dial = func(context.Context, string, string) (net.Conn, error) {
		public.Add(1)
		return nil, errors.New("public escape")
	}
	if _, ip, err := r.Resolve(t.Context(), "www.campus.test"); err == nil || ip != nil || public.Load() != 0 {
		t.Fatal("protected DNS escaped", ip, err, public.Load())
	}
}

var domainResourceMatchSink bool

func TestNativeNamespaceIgnoresCampusRecordsCacheAndDNSFallback(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var original, escaped atomic.Int32
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		original.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(q)
		if strings.HasPrefix(q.Question[0].Name, "missing.") {
			reply.Rcode = dns.RcodeNameError
		} else if q.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		}
		w.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = previous; server.Shutdown(); listener.Close() })
	p, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "mesh.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(nil, "", "", 60, client.DomainResources{".mesh.test": {{Protocol: "tcp", PortMin: 1, PortMax: 65535}}},
		map[string][]net.IP{"host.mesh.test": {net.IPv4(198, 51, 100, 1)}}, true)
	defer r.Close()
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &p }
	forbidden := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		escaped.Add(1)
		return nil, errors.New("campus/public escape")
	}}
	r.remoteUDPResolver, r.remoteTCPResolver, r.secondaryResolver = forbidden, forbidden, forbidden
	r.setDNSCache("host.mesh.test", net.IPv4(203, 0, 113, 1), true)
	ctx, ip, err := r.Resolve(t.Context(), "HOST.MESH.TEST.")
	if err != nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) || original.Load() == 0 || escaped.Load() != 0 || ctx.Value(ContextKeyDomainResource) != nil {
		t.Fatal("protected namespace used campus data", ip, err, original.Load(), escaped.Load())
	}
	if ctx.Value(ContextKeyResolveHost) != "HOST.MESH.TEST." {
		t.Fatal("native absolute query lost its trailing dot")
	}
	if _, ip, err = r.Resolve(t.Context(), "missing.mesh.test"); err == nil || ip != nil || escaped.Load() != 0 {
		t.Fatal("native lookup failure escaped", ip, err)
	}
	queries := original.Load()
	if _, _, err = r.ResolveCampus(t.Context(), "host.mesh.test", true); !errors.Is(err, policy.ErrProtectedTarget) || original.Load() != queries || escaped.Load() != 0 {
		t.Fatal("forced campus path queried a protected namespace", err)
	}
	p, err = policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "mesh.test"}}, []string{"host.mesh.test"})
	if err != nil {
		t.Fatal(err)
	}
	r.dnsCache.Flush()
	ctx, ip, err = r.Resolve(t.Context(), "host.mesh.test")
	if err != nil || !ip.Equal(net.IPv4(198, 51, 100, 1)) || ctx.Value(ContextKeyDomainResource) == nil || original.Load() != queries {
		t.Fatal("exact campus choice did not use authorized campus resolution", ip, err)
	}
	p, _ = policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "mesh.test"}}, nil)
	r.setDNSCache("host.mesh.test", net.IPv4(198, 51, 100, 1), true)
	if _, ip, err := r.Resolve(t.Context(), "host.mesh.test"); err != nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("removed name exception retained a campus cache answer", ip, err)
	}
	entered := make(chan struct{}, 2)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() { _, _, err := r.Resolve(t.Context(), "slow.mesh.test"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native lookup did not start")
	}
	r.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed native lookup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("native lookup survived resolver close")
	}
}

func TestCampusResolutionReusesOnlyTunnelDNSAnswers(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 10)}}
		w.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown(); listener.Close() })
	r := NewResolver(nil, "", "", 60, client.DomainResources{".campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}, nil, true)
	defer r.Close()
	remote := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.LocalAddr().String())
	}}
	r.remoteUDPResolver, r.remoteTCPResolver = remote, remote
	host := "www.campus.test"
	_, ip, err := r.Resolve(t.Context(), host)
	if err != nil || !ip.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatal("campus DNS baseline failed", ip, err)
	}
	first := queries.Load()
	for i := range 3 {
		if i%2 == 0 {
			_, ip, err = r.ResolveCampus(t.Context(), host, true)
		} else {
			_, ip, err = r.Resolve(t.Context(), host)
		}
		if err != nil || !ip.Equal(net.IPv4(192, 0, 2, 10)) || queries.Load() != first {
			t.Fatalf("trusted campus DNS answer was not reused: queries=%d -> %d, IP=%v, error=%v", first, queries.Load(), ip, err)
		}
	}
	r.setDNSCache(host, net.IPv4(203, 0, 113, 10), false)
	_, ip, err = r.ResolveCampus(t.Context(), host, true)
	if err != nil || !ip.Equal(net.IPv4(192, 0, 2, 10)) || queries.Load() <= first {
		t.Fatal("unknown cache origin did not trigger a fresh campus query", ip, err, queries.Load())
	}
}

func TestTCPPrefersL3UsesSelectedResource(t *testing.T) {
	if TCPPrefersL3(context.Background()) {
		t.Fatal("empty context unexpectedly prefers L3")
	}
	domainCtx := context.WithValue(context.Background(), ContextKeyDomainResource, client.DomainResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(domainCtx) {
		t.Fatal("domain resource preference was ignored")
	}
	ipCtx := context.WithValue(context.Background(), ContextKeyIPResource, client.IPResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(ipCtx) {
		t.Fatal("IP resource preference was ignored")
	}
}

func TestMatchDomainResourcePreservesNormalizedSuffixMatching(t *testing.T) {
	want := client.DomainResource{AppID: "vpn-app"}
	index := newDomainResourceIndex(client.DomainResources{".Example.COM.": {want}})
	domain, got, ok := matchDomainResource(index, "service.example.com")
	if !ok {
		t.Fatal("matchDomainResource() did not find normalized suffix")
	}
	if domain != ".Example.COM." || len(got) != 1 || got[0] != want {
		t.Fatalf("matchDomainResource() = (%q, %#v), want original domain and %#v", domain, got, want)
	}
}

func TestDomainResourceMatchRequiresLabelBoundary(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"example.com": {{AppID: "vpn"}}})
	for _, host := range []string{"example.com", "service.example.com"} {
		if _, _, ok := index.Match(host); !ok {
			t.Fatalf("expected %s to match", host)
		}
	}
	if _, _, ok := index.Match("notexample.com"); ok {
		t.Fatal("partial label suffix matched domain resource")
	}
}

func TestWildcardDomainResourceRequiresSubdomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"*.example.com": {{AppID: "vpn"}}})
	if _, _, ok := index.Match("service.example.com"); !ok {
		t.Fatal("wildcard did not match subdomain")
	}
	if _, _, ok := index.Match("example.com"); ok {
		t.Fatal("wildcard unexpectedly matched apex domain")
	}
}

func BenchmarkDomainResourceMatch(b *testing.B) {
	resources := make(client.DomainResources, 1000)
	for i := 0; i < 1000; i++ {
		resources[fmt.Sprintf(".resource-%04d.example", i)] = []client.DomainResource{{}}
	}
	index := newDomainResourceIndex(resources)
	const host = "missing.example.com"

	b.Run("index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, domainResourceMatchSink = index.Match(host)
		}
	})
	b.Run("linear", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			matched := false
			for domain := range resources {
				if strings.HasSuffix(host, normalizeHostname(domain)) {
					matched = true
					break
				}
			}
			domainResourceMatchSink = matched
		}
	})
}

func TestDomainResourceMatchPrefersMostSpecificDomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{
		".cnki.net":    {{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "wildcard"}},
		"www.cnki.net": {{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "exact"}},
	})

	domain, resources, ok := index.Match("www.cnki.net")
	if !ok || domain != "www.cnki.net" || len(resources) != 2 || resources[0].AppID != "exact" {
		t.Fatalf("Match() = (%q, %#v, %v), want exact domain resource", domain, resources, ok)
	}
	if resource, matched := client.MatchDomainResource(resources, "tcp", 443); !matched || resource.AppID != "wildcard" {
		t.Fatalf("443 match = (%#v, %v), want wildcard fallback", resource, matched)
	}
}

func TestResolverReleasesCoordinationEntry(t *testing.T) {
	failing := failingNetResolver()
	resolver := &Resolver{
		remoteUDPResolver: failing,
		remoteTCPResolver: failing,
		secondaryResolver: failing,
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	_, _, _ = resolver.Resolve(context.Background(), "missing.example")
	if entries := resolver.activeResolutions.Load(); entries != 0 {
		t.Fatalf("coordination entries after Resolve = %d, want 0", entries)
	}
}

func TestResolverRotatesConfiguredDNSAddresses(t *testing.T) {
	first := net.ParseIP("192.0.2.1")
	second := net.ParseIP("192.0.2.2")
	resolver := &Resolver{
		domainIndex: newDomainResourceIndex(nil),
		dnsResource: map[string][]net.IP{"service.example": {first, second}},
		dnsCache:    cache.New(time.Minute, 0),
	}

	_, gotFirst, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	_, gotSecond, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if !gotFirst.Equal(first) || !gotSecond.Equal(second) {
		t.Fatalf("rotated addresses = %s, %s, want %s, %s", gotFirst, gotSecond, first, second)
	}
}

func TestResolverWaitingCallerHonorsContext(t *testing.T) {
	started := make(chan struct{}, 1)
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	resolver := &Resolver{
		remoteUDPResolver: blocking,
		remoteTCPResolver: blocking,
		secondaryResolver: failingNetResolver(),
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		_, _, _ = resolver.Resolve(leaderCtx, "blocked.example")
		close(leaderDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader DNS lookup did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	result := make(chan error, 1)
	go func() {
		_, _, err := resolver.Resolve(waiterCtx, "blocked.example")
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting Resolve error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiting Resolve did not stop after context cancellation")
	}

	cancelLeader()
	select {
	case <-leaderDone:
	case <-time.After(time.Second):
		t.Fatal("leader Resolve did not stop after context cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for resolver.activeResolutions.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entries := resolver.activeResolutions.Load(); entries != 0 {
		t.Fatalf("active coordination entries after cancellation = %d after timeout, want 0", entries)
	}
}

func TestResolverLeaderCancellationDoesNotCancelWaiter(t *testing.T) {
	resolver := &Resolver{}
	started := make(chan struct{})
	release := make(chan struct{})
	want := net.ParseIP("192.0.2.20")
	lookup := func(ctx context.Context) (net.IP, error) {
		close(started)
		select {
		case <-release:
			return want, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := resolver.resolveCoordinated(leaderCtx, "shared.example", lookup)
		leaderResult <- err
	}()
	<-started

	waiterResult := make(chan struct {
		ip  net.IP
		err error
	}, 1)
	unexpectedLookup := make(chan struct{}, 1)
	go func() {
		ip, err := resolver.resolveCoordinated(context.Background(), "shared.example", func(context.Context) (net.IP, error) {
			unexpectedLookup <- struct{}{}
			return nil, errors.New("waiter unexpectedly started a second lookup")
		})
		waiterResult <- struct {
			ip  net.IP
			err error
		}{ip: ip, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		resolver.resolutionMu.Lock()
		waiters := resolver.resolutions["shared.example"].waiters
		resolver.resolutionMu.Unlock()
		if waiters == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not join the shared lookup")
		}
		time.Sleep(time.Millisecond)
	}

	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	close(release)
	result := <-waiterResult
	if result.err != nil || !result.ip.Equal(want) {
		t.Fatalf("waiter result = %s, %v, want %s, nil", result.ip, result.err, want)
	}
	select {
	case <-unexpectedLookup:
		t.Fatal("waiter unexpectedly started a second lookup")
	default:
	}
}

func TestLookupIPWithTCPFallbackHedgesSlowUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.10")
	udpCanceled := make(chan struct{})
	udp := func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		close(udpCanceled)
		return nil, ctx.Err()
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	started := time.Now()
	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "slow.example", udp, tcp, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("lookupIPWithTCPFallback() error = %v", err)
	}
	if udpFailed {
		t.Fatal("slow UDP was hedged, not proven failed")
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, want %s", ips, want)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("hedged lookup took %s", elapsed)
	}
	select {
	case <-udpCanceled:
	case <-time.After(time.Second):
		t.Fatal("losing UDP lookup was not canceled")
	}
}

func TestLookupIPWithTCPFallbackKeepsFastUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.11")
	tcpCalled := make(chan struct{}, 1)
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		tcpCalled <- struct{}{}
		return nil, errors.New("unexpected TCP lookup")
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "fast.example", udp, tcp, time.Second)
	if err != nil || udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
	select {
	case <-tcpCalled:
		t.Fatal("TCP lookup started for a fast UDP response")
	default:
	}
}

func TestLookupIPWithTCPFallbackMarksUDPFailure(t *testing.T) {
	want := net.ParseIP("192.0.2.12")
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("UDP unavailable")
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "failed.example", udp, tcp, time.Second)
	if err != nil || !udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
}

func failingNetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS unavailable")
		},
	}
}

func TestCloseJoinsCanceledLookupsAndPanicStaysInWorker(t *testing.T) {
	for _, panics := range []bool{false, true} {
		r := &Resolver{}
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			_, err := r.resolveCoordinated(context.Background(), "fixture", func(ctx context.Context) (net.IP, error) {
				close(started)
				if panics {
					panic("private DNS detail")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			result <- err
		}()
		<-started
		r.Close()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("failed lookup succeeded")
			}
			if panics && err.Error() != "DNS worker panicked" {
				t.Fatalf("panic error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("resolver close left lookup running")
		}
		if r.activeResolutions.Load() != 0 {
			t.Fatal("lookup worker survived Close")
		}
	}
}

func TestDNSCacheRemainsBoundedAndReusesExpiredSlots(t *testing.T) {
	r := NewResolver(nil, "", "", 60, nil, nil, false)
	defer r.Close()
	ip := net.IPv4(192, 0, 2, 1)
	for i := 0; i < maxDNSCacheEntries; i++ {
		r.setDNSCache(fmt.Sprint(i), ip, false)
	}
	r.setDNSCache("overflow", ip, false)
	if r.dnsCache.ItemCount() != maxDNSCacheEntries {
		t.Fatal("DNS cache exceeded its capacity")
	}
	if _, found := r.getDNSCache("overflow", false); found {
		t.Fatal("overflow entry displaced a live record")
	}
	items := r.dnsCache.Items()
	items["0"] = cache.Item{Object: ip, Expiration: time.Now().Add(-time.Second).UnixNano()}
	r.dnsCache = cache.NewFrom(time.Minute, 0, items)
	r.setDNSCache("new", ip, false)
	if _, found := r.getDNSCache("new", false); !found {
		t.Fatal("expired slot was not reclaimed")
	}
}

func TestCampusResolutionRejectsUnknownCacheAndPublicFallback(t *testing.T) {
	campus := net.ParseIP("192.0.2.10")
	r := NewResolver(nil, "", "", 60, nil, map[string][]net.IP{"campus.test": {campus}}, false)
	defer r.Close()
	r.setDNSCache("campus.test", net.ParseIP("203.0.113.10"), false)
	_, ip, err := r.ResolveCampus(t.Context(), "campus.test", false)
	if err != nil || !ip.Equal(campus) {
		t.Fatal("campus lookup used a cache of unknown origin", ip, err)
	}
	calls := 0
	r.secondaryResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unexpected fallback")
	}}
	_, _, err = r.ResolveCampus(t.Context(), "unavailable.campus.test", false)
	if !errors.Is(err, ErrCampusDNSUnavailable) || calls != 0 {
		t.Fatal("campus lookup attempted public fallback", err, calls)
	}
}

func TestAuthorizedDomainResolutionDoesNotFallBackToSecondaryDNS(t *testing.T) {
	r := NewResolver(nil, "", "", 60, client.DomainResources{"campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}, nil, false)
	defer r.Close()
	calls := 0
	r.secondaryResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("public DNS must not receive campus names")
	}}
	r.setDNSCache("campus.test", net.ParseIP("203.0.113.10"), false)
	ctx, ip, err := r.Resolve(t.Context(), "campus.test")
	if !errors.Is(err, ErrCampusDNSUnavailable) || ip != nil || calls != 0 || ctx.Value(ContextKeyDomainResource) == nil {
		t.Fatalf("campus domain used unknown cache/public DNS: IP=%v, calls=%d, error=%v", ip, calls, err)
	}
}
