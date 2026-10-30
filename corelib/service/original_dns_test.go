package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/testdns"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func originalDNSUpstream(t *testing.T, address string, marker byte) (string, *atomic.Int32) {
	t.Helper()
	tcp, udp := testdns.ListenPair(t, address)
	queries := new(atomic.Int32)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg).SetReply(request)
		if strings.HasPrefix(request.Question[0].Name, "failed.") {
			reply.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(reply)
			return
		}
		header := dns.RR_Header{Name: request.Question[0].Name, Rrtype: request.Question[0].Qtype, Class: dns.ClassINET, Ttl: 30}
		if header.Rrtype == dns.TypeDNSKEY {
			reply.Answer = []dns.RR{&dns.DNSKEY{Hdr: header, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "AQID"}}
		} else if header.Rrtype == dns.TypeAAAA {
			reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::9")}}
		} else {
			last := marker
			if strings.HasPrefix(header.Name, "outside.") {
				last = 77
			}
			reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IPv4(203, 0, 113, last)}}
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Net: "tcp", Handler: handler}, {PacketConn: udp, Handler: handler}} {
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go func() { _ = server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	return tcp.Addr().String(), queries
}

func TestOriginalDNSListenerPreservesSourceAndPublication(t *testing.T) {
	iface, local := originalDNSInterface(t)
	upstream, originalQueries := originalDNSUpstream(t, local.String(), 9)
	alternateUpstream, alternateQueries := originalDNSUpstream(t, local.String(), 11)
	loopbackUpstream, _ := originalDNSUpstream(t, "127.0.0.1", 12)
	campusUpstream, campusQueries := originalDNSUpstream(t, "127.0.0.1", 10)
	campus := &ingressCampus{tcpAddress: campusUpstream, udpAddress: campusUpstream, called: make(chan string, 32)}
	r := resolve.NewResolver(campus, "203.0.113.7", "", 30,
		client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, true)
	t.Cleanup(r.Close)
	var protection atomic.Pointer[policy.ProtectionPolicy]
	setChoice := func(campusNames []string) {
		value, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "campus.test"}}, campusNames)
		if err != nil {
			t.Fatal(err)
		}
		protection.Store(&value)
	}
	setChoice(nil)
	r.ProtectionPolicy = protection.Load
	var err error
	base := resolve.OriginalDNSRoute{Name: policy.NameRule{Kind: "suffix", Value: "campus.test"},
		Servers: []string{upstream}, Interface: iface, Source: iface, Listen: net.JoinHostPort(local.String(), "0")}
	shared, alternate, split := base, base, base
	shared.Name = policy.NameRule{Kind: "exact", Value: "shared.campus.test"}
	alternate.Source, alternate.Servers = iface+":alternate", []string{alternateUpstream}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagLoopback != 0 && candidate.Flags&net.FlagUp != 0 {
			split.Interface = candidate.Name
			break
		}
	}
	if split.Interface == iface {
		t.Fatal("no loopback query interface for the local original resolver")
	}
	split.Name = policy.NameRule{Kind: "exact", Value: "host.split.test"}
	split.Source, split.Servers = iface+":split", []string{loopbackUpstream}
	r.OriginalDNS, err = resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{base, shared, alternate, split})
	if err != nil {
		t.Fatal(err)
	}
	d := dial.NewDialer(campus, r, []client.IPResource{ingressResource("all", resolve.DNSPort)}, false)
	d.ProtectionPolicy = protection.Load
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	endpoint := p.OriginalDNSListeners()[iface]
	query := func(transport, name string, qtype uint16) (*dns.Msg, error) {
		answer, _, err := (&dns.Client{Net: transport, Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion(name, qtype), endpoint)
		return answer, err
	}
	type result struct {
		answer *dns.Msg
		err    error
	}
	answer := make(chan result, 1)
	go func() { reply, err := query("udp", "private.campus.test.", dns.TypeA); answer <- result{reply, err} }()
	until := time.Now().Add(5 * time.Second)
	for len(p.dnsWorkers) == 0 && time.Now().Before(until) {
		runtime.Gosched()
	}
	if len(p.dnsWorkers) != 1 || originalQueries.Load() != 0 || campusQueries.Load() != 0 {
		t.Fatal("native DNS escaped before TUN preparation")
	}
	publication := make(chan []netip.Addr, 8)
	acknowledged := make(chan struct{})
	var publications atomic.Int32
	if err := p.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, func(ctx context.Context, addresses []netip.Addr, exclude bool) error {
		if (addresses[0].String() == "203.0.113.10") == exclude {
			t.Error("wrong native/campus publication direction", addresses, exclude)
		}
		if publications.Add(1) == 1 {
			publication <- addresses
			select {
			case <-acknowledged:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case addresses := <-publication:
		if !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("203.0.113.9")}) || slices.Contains(p.ActiveTUNAddresses(), "203.0.113.9") || !slices.Contains(p.OriginalDNSRecords()["private.campus.test"], "203.0.113.9") {
			t.Fatal("native DNS publication lost its pending exclusion", addresses)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native DNS did not reach its shared route publisher")
	}
	select {
	case early := <-answer:
		t.Fatal("native DNS replied before exclusion confirmation", early)
	default:
	}
	close(acknowledged)
	first := <-answer
	if first.err != nil || first.answer.Rcode != dns.RcodeSuccess || len(first.answer.Answer) != 1 || first.answer.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
		t.Fatal(first)
	}
	for _, transport := range []string{"udp", "tcp"} {
		before := publications.Load()
		root, err := query(transport, ".", dns.TypeDNSKEY)
		if err != nil || len(root.Answer) != 1 || root.Answer[0].Header().Rrtype != dns.TypeDNSKEY || publications.Load() != before {
			t.Fatal("native DNSSEC root query was blocked or captured", root, err)
		}
		for _, name := range []string{"outside.test.", "outside.more.test."} {
			reply, err := query(transport, name, dns.TypeA)
			if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.77" {
				t.Fatal("public query lost its native source", reply, err)
			}
		}
		if publications.Load() != before || slices.Contains(p.ActiveTUNAddresses(), "203.0.113.77") || len(p.OriginalDNSRecords()["outside.test"]) != 0 {
			t.Fatal("public DNS polluted protected bindings or capture routes")
		}
		campusBefore := campusQueries.Load()
		reply, err := query(transport, "private.campus.test.", dns.TypeAAAA)
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypeAAAA || campusQueries.Load() != campusBefore {
			t.Fatal("native AAAA was sent to campus or discarded", reply, err)
		}
		setChoice([]string{"private.campus.test"})
		reply, err = query(transport, "private.campus.test.", dns.TypeA)
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
			t.Fatal("confirmed campus choice did not use campus DNS", reply, err)
		}
		setChoice(nil)
		reply, err = query(transport, "private.campus.test.", dns.TypeA)
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
			t.Fatal("withdrawal lost original DNS direction", reply, err)
		}
	}
	before := originalQueries.Load() + campusQueries.Load()
	if reply, err := query("udp", "localhost.", dns.TypeA); err != nil || reply.Rcode != dns.RcodeRefused || before != originalQueries.Load()+campusQueries.Load() {
		t.Fatal("localhost escaped native local resolution", reply, err)
	}
	endpoints := p.OriginalDNSListeners()
	if len(endpoints) != 3 || endpoints[iface] == endpoints[alternate.Source] {
		t.Fatal("native scopes were not grouped by their actual source context", endpoints)
	}
	for _, transport := range []string{"udp", "tcp"} {
		for source, want := range map[string]string{iface: "203.0.113.9", alternate.Source: "203.0.113.11"} {
			reply, _, err := (&dns.Client{Net: transport, Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion("private.campus.test.", dns.TypeA), endpoints[source])
			if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != want {
				t.Fatal("overlapping native DNS contexts lost their selected source", source, reply, err)
			}
			if actual, err := r.OriginalDNSProtectedIP(t.Context(), netip.MustParseAddr(want)); err != nil || !actual {
				t.Fatal("overlapping DNS sources lost their original data direction", actual, err)
			}
		}
	}
	if alternateQueries.Load() != 2 {
		t.Fatal("a native listener queried another source context")
	}
	splitAnswer, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion("split.campus.test.", dns.TypeA), endpoints[split.Source])
	if err != nil || len(splitAnswer.Answer) != 1 || splitAnswer.Answer[0].(*dns.A).A.String() != "203.0.113.12" {
		t.Fatal("listener interface was incorrectly used as the query interface", splitAnswer, err)
	}
	if actual, err := r.OriginalDNSProtectedIP(t.Context(), netip.MustParseAddr("203.0.113.12")); err != nil || !actual {
		t.Fatal("query and data exits were conflated", actual, err)
	}
	disabled := resolve.NewResolver(campus, "203.0.113.7", "", 30,
		client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, false)
	t.Cleanup(disabled.Close)
	disabled.OriginalDNS = r.OriginalDNS
	disabledListeners, err := NewListeners(t.Context(), "", "", dial.NewDialer(campus, disabled, nil, false), disabled)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(disabledListeners.Close)
	if err := disabledListeners.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, nil); err != nil {
		t.Fatal(err)
	}
	campusBefore := campusQueries.Load()
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion("private.campus.test.", qtype), disabledListeners.OriginalDNSListeners()[iface])
		if err != nil || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != qtype || campusQueries.Load() != campusBefore || len(disabled.CampusDNSRecords()) != 0 {
			t.Fatal("disabled campus DNS changed native resolution or created a campus grant", reply, err)
		}
	}
	closeIngress(t, disabledListeners)
	closeIngress(t, p)
	tcp, err := net.Listen("tcp4", endpoint)
	if err != nil {
		t.Fatal("closed DNS listener retained its TCP port", err)
	}
	tcp.Close()
	udp, err := net.ListenPacket("udp4", endpoint)
	if err != nil {
		t.Fatal("closed DNS listener retained its UDP port", err)
	}
	udp.Close()
}

func TestOriginalDNSListenerDispatchesNativeScopesWithoutGuessingFallback(t *testing.T) {
	for _, explicitDefault := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-default", true: "confirmed-default"}[explicitDefault], func(t *testing.T) {
			iface, local := originalDNSInterface(t)
			upstream, queries := originalDNSUpstream(t, local.String(), 9)
			specialUpstream, specialQueries := originalDNSUpstream(t, local.String(), 11)
			r := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
			t.Cleanup(r.Close)
			base := resolve.OriginalDNSRoute{Name: policy.NameRule{Kind: "suffix", Value: "original.test"},
				Servers: []string{upstream}, Interface: iface, Source: "native-scopes", Listen: net.JoinHostPort(local.String(), "0"), Default: explicitDefault}
			first, special := base, base
			first.Default = false
			first.Name = policy.NameRule{Kind: "exact", Value: "first.original.test"}
			special.Default = false
			special.Name = policy.NameRule{Kind: "suffix", Value: "special.original.test"}
			special.Servers = []string{specialUpstream}
			routes := []resolve.OriginalDNSRoute{first, special, base}
			var err error
			r.OriginalDNS, err = resolve.NewOriginalDNS(routes)
			if err != nil {
				t.Fatal(err)
			}
			routes[1].Servers[0] = upstream
			protection, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{base.Name}, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protection }
			d := dial.NewDialer(nil, r, nil, false)
			d.ProtectionPolicy = r.ProtectionPolicy
			p, err := NewListeners(t.Context(), "", "", d, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			var publications atomic.Int32
			if err := p.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, func(_ context.Context, _ []netip.Addr, exclude bool) error {
				if !exclude {
					t.Error("original scope granted a campus capture")
				}
				publications.Add(1)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			endpoints := p.OriginalDNSListeners()
			if len(endpoints) != 1 {
				t.Fatal("native scopes did not share one listener", endpoints)
			}
			for _, transport := range []string{"udp", "tcp"} {
				query := func(name string, qtype uint16) *dns.Msg {
					reply, _, err := (&dns.Client{Net: transport, Timeout: 5 * time.Second}).ExchangeContext(t.Context(),
						new(dns.Msg).SetQuestion(name, qtype), endpoints[base.Source])
					if err != nil {
						t.Fatal(err)
					}
					return reply
				}
				for _, target := range []struct{ name, address string }{
					{"first.original.test.", "203.0.113.9"}, {"host.special.original.test.", "203.0.113.11"}, {"host.original.test.", "203.0.113.9"},
				} {
					reply := query(target.name, dns.TypeA)
					if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != target.address {
						t.Fatal("native scope precedence or immutable upstream lost", target, reply)
					}
				}
				before, specialBefore := queries.Load(), specialQueries.Load()
				if reply := query("failed.special.original.test.", dns.TypeA); reply.Rcode != dns.RcodeServerFailure || queries.Load() != before || specialQueries.Load() != specialBefore+1 {
					t.Fatal("failed scope fell back to another native server", reply)
				}
				before, specialBefore = queries.Load(), specialQueries.Load()
				published := publications.Load()
				for _, question := range []struct {
					name  string
					qtype uint16
				}{{"outside.test.", dns.TypeA}, {".", dns.TypeDNSKEY}} {
					reply := query(question.name, question.qtype)
					if explicitDefault {
						if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != question.qtype {
							t.Fatal("confirmed native default did not answer unmatched/root query", question, reply)
						}
						if question.qtype == dns.TypeA && reply.Answer[0].(*dns.A).A.String() != "203.0.113.77" {
							t.Fatal("unmatched query reached another native server", reply)
						}
					} else if reply.Rcode != dns.RcodeRefused {
						t.Fatal("ambiguous unmatched native scope was guessed", question, reply)
					}
				}
				for _, name := range []string{"localhost.", "-bad.original.test."} {
					if reply := query(name, dns.TypeA); reply.Rcode != dns.RcodeRefused {
						t.Fatal("native default forwarded a local or malformed name", name, reply)
					}
				}
				if explicitDefault {
					before += 2
				}
				if queries.Load() != before || specialQueries.Load() != specialBefore || publications.Load() != published {
					t.Fatal("native default changed scope, publication or invalid-name boundaries")
				}
			}
			expected := int32(4)
			if explicitDefault {
				expected += 4
			}
			if queries.Load() != expected || specialQueries.Load() != 4 {
				t.Fatal("scope dispatch used a different original server", queries.Load(), specialQueries.Load())
			}

		})
	}
}

func TestOriginalDNSRejectsForeignPeers(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	for _, peer := range []string{"192.0.2.2", "203.0.113.1", "0.0.0.0", "224.0.0.1"} {
		if localDNSPeer(netip.MustParseAddr(peer), local) {
			t.Fatal("non-local peer entered the native DNS relay", peer)
		}
	}
}

func TestOriginalDNSPreparationBeforeDeviceIsAtomicAndSealed(t *testing.T) {
	iface, local := originalDNSInterface(t)
	upstream, _ := originalDNSUpstream(t, local.String(), 9)
	r := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	defer r.Close()
	p, err := NewListeners(t.Context(), "127.0.0.1:0", "", dial.NewDialer(nil, r, nil, false), r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	base := resolve.OriginalDNSRoute{Name: policy.NameRule{Kind: "suffix", Value: "original.test"}, Servers: []string{upstream},
		Source: iface, Listen: net.JoinHostPort(local.String(), "0")}
	compile := func(route resolve.OriginalDNSRoute) *resolve.OriginalDNS {
		value, err := resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{route})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, name := range []string{"unavailable interface", "unassigned address"} {
		t.Run(name, func(t *testing.T) {
			bad := base
			if name == "unavailable interface" {
				bad.Interface = "JustConnect-missing-query-interface"
			} else {
				bad.Listen = "192.0.2.254:0"
			}
			err := p.PrepareOriginalDNS(compile(bad))
			if err == nil || err.Error() != "original DNS requires an available query interface and assigned local listener address" ||
				r.OriginalDNS != nil || len(p.OriginalDNSListeners()) != 0 {
				t.Fatal("invalid interface/address passed native DNS preparation or changed active sources", err)
			}
		})
	}
	// Reserve both transports before leaving UDP occupied; their excluded port ranges can differ.
	tcp, occupied := testdns.ListenPair(t, local.String())
	tcp.Close()
	defer occupied.Close()
	bad := base
	bad.Listen = occupied.LocalAddr().String()
	if err := p.PrepareOriginalDNS(compile(bad)); err == nil || r.OriginalDNS != nil || len(p.OriginalDNSListeners()) != 0 {
		t.Fatal("failed preparation changed the active resolver or exposed partial endpoints", err)
	}
	proxy, err := net.DialTimeout("tcp4", p.listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal("preparation failure closed the running proxy", err)
	}
	_ = proxy.SetDeadline(time.Now().Add(time.Second))
	if _, err := proxy.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(proxy, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("proxy did not survive source failure", greeting, err)
	}
	proxy.Close()
	tcp, err = net.Listen("tcp4", bad.Listen)
	if err != nil {
		t.Fatal("failed preparation retained its TCP socket", err)
	}
	tcp.Close()
	occupied.Close()
	first, second := bad, bad
	first.Source, second.Source = iface+":first", iface+":second"
	conflict, err := resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PrepareOriginalDNS(conflict); err == nil || r.OriginalDNS != nil || len(p.OriginalDNSListeners()) != 0 {
		t.Fatal("multi-source conflict committed a partial preparation", err)
	}
	tcp, err = net.Listen("tcp4", bad.Listen)
	if err != nil {
		t.Fatal("failed multi-source preparation retained TCP", err)
	}
	udp, err := net.ListenPacket("udp4", bad.Listen)
	if err != nil {
		t.Fatal("failed multi-source preparation retained its earlier UDP socket", err)
	}
	tcp.Close()
	udp.Close()
	prepared := compile(base)
	if err := p.PrepareOriginalDNS(prepared); err != nil {
		t.Fatal("retry after bind failure", err)
	}
	endpoint := p.OriginalDNSListeners()[iface]
	if endpoint == "" || r.OriginalDNS != prepared {
		t.Fatal("prepared endpoints were not committed together")
	}
	if err := p.PrepareOriginalDNS(compile(base)); !errors.Is(err, ErrOriginalDNSSealed) {
		t.Fatal("a prepared source set was replaced", err)
	}
	if err := p.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.PrepareOriginalDNS(compile(base)); !errors.Is(err, ErrOriginalDNSSealed) {
		t.Fatal(err)
	}
	closeIngress(t, p)
	if err := p.PrepareOriginalDNS(compile(base)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed session prepared sources", err)
	}
	tcp, err = net.Listen("tcp4", endpoint)
	if err != nil {
		t.Fatal("prepared TCP endpoint survived close", err)
	}
	tcp.Close()
	udp, err = net.ListenPacket("udp4", endpoint)
	if err != nil {
		t.Fatal("prepared UDP endpoint survived close", err)
	}
	udp.Close()
	other := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	defer other.Close()
	attached, err := NewListeners(t.Context(), "", "", dial.NewDialer(nil, other, nil, false), other)
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	if err := attached.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, nil); err != nil {
		t.Fatal(err)
	}
	if err := attached.PrepareOriginalDNS(compile(base)); !errors.Is(err, ErrOriginalDNSSealed) || other.OriginalDNS != nil {
		t.Fatal("device attachment did not seal source preparation", err)
	}
	legacy := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	defer legacy.Close()
	protected, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{base.Name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protected }
	plain, err := NewListeners(t.Context(), "", "", nil, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	explicit := base
	explicit.Source = ""
	explicit.Listen = ""
	if err := plain.PrepareOriginalDNS(compile(explicit)); err != nil {
		t.Fatal(err)
	}
	reply, err := legacy.ExchangeTUN(t.Context(), new(dns.Msg).SetQuestion("host.original.test.", dns.TypeA), "udp", nil, nil)
	if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.9" || len(plain.OriginalDNSListeners()) != 0 {
		t.Fatal("explicit sources without native listeners did not prepare their original forwarding", reply, err)
	}
	if err := plain.PrepareOriginalDNS(compile(base)); !errors.Is(err, ErrOriginalDNSSealed) {
		t.Fatal("explicit sources were not sealed", err)
	}
}

func TestOriginalDNSCloseBeforeTUNAndPartialBindFailure(t *testing.T) {
	iface, local := originalDNSInterface(t)
	tcp, occupied := testdns.ListenPair(t, local.String())
	defer occupied.Close()
	endpoint := occupied.LocalAddr().String()
	tcp.Close()
	r := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	defer r.Close()
	configure := func(address string) {
		compiled, err := resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{{Name: policy.NameRule{Kind: "suffix", Value: "original.test"},
			Servers: []string{occupied.LocalAddr().String()}, Interface: iface, Source: iface, Listen: address}})
		if err != nil {
			t.Fatal(err)
		}
		r.OriginalDNS = compiled
	}
	configure(endpoint)
	if p, err := NewListeners(t.Context(), "", "", nil, r); err == nil {
		p.Close()
		t.Fatal("occupied UDP endpoint did not fail DNS preparation")
	}
	tcp, err := net.Listen("tcp4", endpoint)
	if err != nil {
		t.Fatal("failed DNS preparation retained its earlier TCP listener", err)
	}
	tcp.Close()
	configure(net.JoinHostPort(local.String(), "0"))
	p, err := NewListeners(t.Context(), "", "", nil, r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	endpoint = p.OriginalDNSListeners()[iface]
	idle, err := net.Dial("tcp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan bool, 1)
	go func() {
		answer, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(ctx, new(dns.Msg).SetQuestion("host.original.test.", dns.TypeA), endpoint)
		result <- err == nil && answer.Rcode == dns.RcodeSuccess
	}()
	until := time.Now().Add(5 * time.Second)
	for len(p.dnsWorkers) != 2 && time.Now().Before(until) {
		runtime.Gosched()
	}
	if len(p.dnsWorkers) != 2 {
		t.Fatal("idle TCP and pre-TUN UDP requests did not enter the bounded worker set")
	}
	flood, err := net.Dial("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer flood.Close()
	until = time.Now().Add(5 * time.Second)
	_ = flood.SetWriteDeadline(until)
	packet, err := new(dns.Msg).SetQuestion("host.original.test.", dns.TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	for len(p.dnsWorkers) < cap(p.dnsWorkers) && time.Now().Before(until) {
		if _, err := flood.Write(packet); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
	}
	if len(p.dnsWorkers) != cap(p.dnsWorkers) {
		t.Fatal("native DNS workload did not reach its bounded capacity")
	}
	for index := 0; index < cap(p.dnsWorkers); index++ {
		if _, err := flood.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("DNS shutdown did not interrupt idle and pre-TUN requests")
	}
	cancel()
	if success := <-result; success || len(p.OriginalDNSListeners()) != 0 {
		t.Fatal("closed preparation returned usable DNS state")
	}
}
