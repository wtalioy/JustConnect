package service

import (
	"context"
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
		client.DomainResources{"*.campus.test": {{Protocol: "all", PortMin: 1, PortMax: 65535}}}, nil, true)
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
	if err := p.AttachTUN(device, 1400); err != nil {
		t.Fatal(err)
	}
	peer := tunPeer(t, device.packetDevice)
	target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: resolve.DNSPort}
	query := func(transport string, message *dns.Msg) *dns.Msg {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var conn net.Conn
		var err error
		if transport == "tcp" {
			conn, err = gonet.DialContextTCP(ctx, peer, target, ipv4.ProtocolNumber)
		} else {
			conn, err = gonet.DialUDP(peer, nil, &target, ipv4.ProtocolNumber)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		reply, _, err := (&dns.Client{Net: transport}).ExchangeWithConnContext(ctx, message, &dns.Conn{Conn: conn, UDPSize: 4096})
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	request := new(dns.Msg).SetQuestion("alias.campus.test.", dns.TypeA)
	reply := query("udp", request)
	if !reply.Truncated || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("large UDP response did not request TCP: %v", reply)
	}
	reply = query("tcp", request)
	if reply.Truncated || len(reply.Answer) != 81 || reply.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("TCP/CNAME records lost: %v", reply)
	}
	before := upstream.Load()
	for _, entry := range []struct {
		host string
		kind uint16
		code int
	}{
		{"outside.test.", dns.TypeA, dns.RcodeRefused}, {"alias.campus.test.", dns.TypeAAAA, dns.RcodeNotImplemented},
	} {
		if reply := query("udp", new(dns.Msg).SetQuestion(entry.host, entry.kind)); reply.Rcode != entry.code {
			t.Fatalf("wrong DNS refusal: %v", reply)
		}
	}
	blocked, err := policy.NewProtectionPolicy([]string{"203.0.113.7/32"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&blocked)
	if reply := query("tcp", request); reply.Rcode != dns.RcodeRefused {
		t.Fatalf("protected DNS upstream was used: %v", reply)
	}
	if upstream.Load() != before {
		t.Fatal("refused questions generated campus traffic")
	}
	closeIngress(t, p)
}
