package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type dnsPacketDevice struct{ *packetDevice }

func (*dnsPacketDevice) TUNAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
}

func TestTUNDNSUsesOwnedPeerAndCampusACL(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var upstream atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		upstream.Add(1)
		reply := new(dns.Msg).SetReply(request)
		reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "target.campus.test."}}
		for index := 0; index < 80; index++ {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: "target.campus.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.IPv4(203, 0, 113, byte(index+1))})
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcpListener, Net: "tcp", Handler: handler}, {PacketConn: udpSocket, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	campus := &ingressCampus{tcpAddress: tcpListener.Addr().String(), udpAddress: udpSocket.LocalAddr().String(), called: make(chan string, 32)}
	r := resolve.NewResolver(campus, "203.0.113.7", "", 30,
		client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, true)
	t.Cleanup(r.Close)
	var protection atomic.Pointer[policy.ProtectionPolicy]
	r.ProtectionPolicy = protection.Load
	d := dial.NewDialer(campus, r, []client.IPResource{ingressResource("all", resolve.DNSPort)}, false)
	d.ProtectionPolicy = protection.Load
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	device := &dnsPacketDevice{newPacketDevice()}
	var publicationMode atomic.Int32
	publications := make(chan []netip.Addr, 16)
	release := make(chan bool)
	publicationCancelled := make(chan struct{})
	publish := func(ctx context.Context, addresses []netip.Addr) error {
		publications <- append([]netip.Addr(nil), addresses...)
		if publicationMode.Load() == 0 {
			return nil
		}
		select {
		case applied := <-release:
			if applied {
				return nil
			}
			return errors.New("owned helper refused publication")
		case <-ctx.Done():
			close(publicationCancelled)
			return ctx.Err()
		}
	}
	if err := p.AttachTUN(device, 1400, publish); err != nil {
		t.Fatal(err)
	}
	peer := tunPeer(t, device.packetDevice)
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: resolve.DNSPort}
	exchange := func(transport string, destination tcpip.FullAddress, message *dns.Msg) (*dns.Msg, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var conn net.Conn
		var err error
		if transport == "tcp" {
			conn, err = gonet.DialContextTCP(ctx, peer, destination, ipv4.ProtocolNumber)
		} else {
			conn, err = gonet.DialUDP(peer, nil, &destination, ipv4.ProtocolNumber)
		}
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		reply, _, err := (&dns.Client{Net: transport}).ExchangeWithConnContext(ctx, message, &dns.Conn{Conn: conn, UDPSize: 4096})
		return reply, err
	}
	query := func(transport string, destination tcpip.FullAddress, message *dns.Msg) *dns.Msg {
		t.Helper()
		reply, err := exchange(transport, destination, message)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
	reply := query("udp", target, request)
	if !reply.Truncated || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("large UDP response did not request TCP: %v", reply)
	}
	reply = query("tcp", target, request)
	if reply.Truncated || len(reply.Answer) != 81 || reply.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("TCP/CNAME records lost: %v", reply)
	}
	for index := 0; index < 2; index++ {
		addresses := <-publications
		if len(addresses) != 80 || addresses[0] != netip.MustParseAddr("203.0.113.1") || addresses[79] != netip.MustParseAddr("203.0.113.80") {
			t.Fatal("route publication lost the validated CNAME address set", addresses)
		}
	}
	publicationMode.Store(1)
	for _, applied := range []bool{true, false} {
		type queryResult struct {
			reply *dns.Msg
			err   error
		}
		result := make(chan queryResult, 1)
		go func() { reply, err := exchange("tcp", target, request); result <- queryResult{reply, err} }()
		select {
		case <-publications:
		case reply := <-result:
			t.Fatalf("DNS completed before route publication: %v, %v", reply.reply, reply.err)
		case <-time.After(5 * time.Second):
			t.Fatal("DNS route publication did not start within the query deadline")
		}
		select {
		case reply := <-result:
			t.Fatal("DNS replied before owned route acknowledgement", reply)
		case <-time.After(25 * time.Millisecond):
		}
		select {
		case release <- applied:
		case reply := <-result:
			t.Fatalf("DNS completed before route acknowledgement: %v, %v", reply.reply, reply.err)
		}
		answer := <-result
		if answer.err != nil {
			t.Fatal(answer.err)
		}
		reply := answer.reply
		want := dns.RcodeServerFailure
		if applied {
			want = dns.RcodeSuccess
		}
		if reply.Rcode != want || (!applied && len(reply.Answer) != 0) {
			t.Fatal("publication result ignored", reply)
		}
	}
	publicationMode.Store(0)
	local, ownedPeer := device.TUNAddresses()
	for _, address := range p.ActiveTUNAddresses() {
		if address == local.String() || address == ownedPeer.String() {
			t.Fatal("owned DNS endpoints became external capture targets", address)
		}
	}
	application := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 9}), Port: 80}
	if reply := query("tcp", application, request); len(reply.Answer) != 81 {
		t.Fatal("DNS-authorized transparent TCP lost data without an IP resource", reply)
	}
	protectedAnswer, err := policy.NewProtectionPolicy([]string{"203.0.113.9/32"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&protectedAnswer)
	if reply := query("tcp", target, request); reply.Rcode != dns.RcodeRefused {
		t.Fatal("protected answer was captured", reply)
	}
	select {
	case addresses := <-publications:
		t.Fatal("protected addresses reached the helper", addresses)
	default:
	}
	protection.Store(nil)
	before := upstream.Load()
	for _, entry := range []struct {
		host string
		kind uint16
		code int
	}{
		{"outside.test.", dns.TypeA, dns.RcodeRefused}, {"alias.campus.test.", dns.TypeAAAA, dns.RcodeNotImplemented},
	} {
		if reply := query("udp", target, new(dns.Msg).SetQuestion(entry.host, entry.kind)); reply.Rcode != entry.code {
			t.Fatalf("wrong DNS refusal: %v", reply)
		}
	}
	blocked, err := policy.NewProtectionPolicy([]string{"203.0.113.7/32"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&blocked)
	if reply := query("tcp", target, request); reply.Rcode != dns.RcodeRefused {
		t.Fatalf("protected DNS upstream was used: %v", reply)
	}
	if upstream.Load() != before {
		t.Fatal("refused questions generated campus traffic")
	}
	protection.Store(nil)
	publicationMode.Store(1)
	conn, err := gonet.DialContextTCP(t.Context(), peer, target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stopped := make(chan error, 1)
	go func() {
		_, _, err := (&dns.Client{Net: "tcp"}).ExchangeWithConnContext(t.Context(), request, &dns.Conn{Conn: conn})
		stopped <- err
	}()
	<-publications
	closeIngress(t, p)
	select {
	case <-publicationCancelled:
	default:
		t.Fatal("shutdown did not cancel pending DNS publication")
	}
	// The detached test link cannot deliver a peer FIN; close the simulated host's socket.
	_ = conn.Close()
	select {
	case err := <-stopped:
		if err == nil {
			t.Fatal("shutdown returned a successful unpublished DNS reply")
		}
	case <-time.After(time.Second):
		t.Fatal("simulated DNS caller did not exit after its socket closed")
	}
}
