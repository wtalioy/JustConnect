package service

import (
	"context"
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
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func originalDNSUpstream(t *testing.T, address string, marker byte) (string, *atomic.Int32) {
	t.Helper()
	tcp, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	queries := new(atomic.Int32)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg).SetReply(request)
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
		Servers: []string{upstream}, Interface: iface, EgressInterface: iface, Source: iface, Listen: net.JoinHostPort(local.String(), "0")}
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
	if err := p.AttachTUN(&dnsPacketDevice{newPacketDevice()}, 1400, func(ctx context.Context, addresses []netip.Addr) error {
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
		if !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("203.0.113.9")}) || !slices.Contains(p.ActiveTUNAddresses(), "203.0.113.9") {
			t.Fatal("native DNS publication lost its pending capture", addresses)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native DNS did not reach its shared route publisher")
	}
	select {
	case early := <-answer:
		t.Fatal("native DNS replied before capture confirmation", early)
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
			if actual, err := r.OriginalInterfaceForIP(t.Context(), netip.MustParseAddr(want)); err != nil || actual != iface {
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
	if actual, err := r.OriginalInterfaceForIP(t.Context(), netip.MustParseAddr("203.0.113.12")); err != nil || actual != iface {
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

func TestOriginalDNSRejectsForeignPeers(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	for _, peer := range []string{"192.0.2.2", "203.0.113.1", "0.0.0.0", "224.0.0.1"} {
		if localDNSPeer(netip.MustParseAddr(peer), local) {
			t.Fatal("non-local peer entered the native DNS relay", peer)
		}
	}
}

func TestOriginalDNSCloseBeforeTUNAndPartialBindFailure(t *testing.T) {
	iface, local := originalDNSInterface(t)
	occupied, err := net.ListenPacket("udp4", net.JoinHostPort(local.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	endpoint := occupied.LocalAddr().String()
	tcp, err := net.Listen("tcp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tcp.Close()
	r := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	defer r.Close()
	configure := func(address string) {
		r.OriginalDNS, err = resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{{Name: policy.NameRule{Kind: "suffix", Value: "original.test"},
			Servers: []string{occupied.LocalAddr().String()}, Interface: iface, EgressInterface: iface, Source: iface, Listen: address}})
		if err != nil {
			t.Fatal(err)
		}
	}
	configure(endpoint)
	if p, err := NewListeners(t.Context(), "", "", nil, r); err == nil {
		p.Close()
		t.Fatal("occupied UDP endpoint did not fail DNS preparation")
	}
	tcp, err = net.Listen("tcp4", endpoint)
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
