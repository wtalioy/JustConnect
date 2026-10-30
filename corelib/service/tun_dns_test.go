package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/pprof"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/testdns"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type dnsPacketDevice struct{ *packetDevice }

func (*dnsPacketDevice) TUNAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
}

type tracedDNSDevice struct {
	*dnsPacketDevice
	mu      sync.Mutex
	packets []string
}

func (d *tracedDNSDevice) record(direction string, packet []byte) {
	if len(packet) < header.IPv4MinimumSize || header.IPv4(packet).TransportProtocol() != tcp.ProtocolNumber {
		return
	}
	segment := header.TCP(header.IPv4(packet).Payload())
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.packets) < 128 {
		d.packets = append(d.packets, fmt.Sprintf("%s %s %d->%d seq=%d ack=%d flags=%s window=%d bytes=%d", time.Now().Format("15:04:05.000000"), direction,
			segment.SourcePort(), segment.DestinationPort(), segment.SequenceNumber(), segment.AckNumber(), segment.Flags(), segment.WindowSize(), len(segment.Payload())))
	}
}
func (d *tracedDNSDevice) Read(packet []byte) (int, error) {
	n, err := d.packetDevice.Read(packet)
	if err == nil {
		d.record("host->ingress", packet[:n])
	}
	return n, err
}
func (d *tracedDNSDevice) Write(packet []byte) (int, error) {
	d.record("ingress->host", packet)
	return d.packetDevice.Write(packet)
}
func (d *tracedDNSDevice) diagnose(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	for _, packet := range d.packets {
		t.Log(packet)
	}
	d.mu.Unlock()
	var stacks bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
	t.Log(stacks.String())
}

func originalDNSInterface(t *testing.T) (string, net.IP) {
	t.Helper()
	var iface string
	var localIP net.IP
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range interfaces {
		if row.Flags&net.FlagLoopback != 0 || row.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := row.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && ip.IsGlobalUnicast() {
				local, peer := new(dnsPacketDevice).TUNAddresses()
				candidate := netip.MustParseAddr(ip.String())
				if candidate == local || candidate == peer {
					continue
				}
				iface, localIP = row.Name, ip.To4()
				break
			}
		}
		if localIP != nil {
			break
		}
	}
	if localIP == nil {
		t.Fatal("no active unicast IPv4 interface for original DNS traffic")
	}
	return iface, localIP
}

func TestTUNOriginalDNSExcludesCaptureAndRejectsRecapturedData(t *testing.T) {
	iface, localIP := originalDNSInterface(t)
	tcp, udp := testdns.ListenPair(t, localIP.String())
	var queries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg).SetReply(request)
		address := localIP
		if request.Question[0].Name == "capture.original.test." {
			address = net.IPv4(203, 0, 113, 9)
		}
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: address}}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Net: "tcp", Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	protected, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "suffix", Value: "original.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := resolve.NewResolver(nil, "", "", 30, nil, nil, false)
	t.Cleanup(r.Close)
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protected }
	r.OriginalDNS, err = resolve.NewOriginalDNS([]resolve.OriginalDNSRoute{{Name: policy.NameRule{Kind: "suffix", Value: "original.test"}, Servers: []string{tcp.Addr().String()}, Interface: iface}})
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
	device := &dnsPacketDevice{newPacketDevice()}
	var publications atomic.Int32
	if err := p.AttachTUN(device, 1400, func(_ context.Context, addresses []netip.Addr, exclude bool) error {
		address := netip.MustParseAddr("203.0.113.9")
		if !exclude || len(addresses) != 1 || slices.Contains(p.ActiveTUNAddresses(), addresses[0].String()) || (addresses[0] == address && (len(r.OriginalDNSRecords()["capture.original.test"]) != 0 || !slices.Contains(p.OriginalDNSRecords()["capture.original.test"], address.String()))) {
			t.Error("original exclusion was absent or became a campus capture before acknowledgement", addresses)
		}
		publications.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	peer := tunPeer(t, device.packetDevice)
	for _, transport := range []string{"udp", "tcp"} {
		for _, entry := range []struct {
			host string
			addr [4]byte
			port uint16
		}{
			{"data.original.test.", [4]byte{198, 18, 0, 2}, resolve.DNSPort},
		} {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(entry.addr), Port: entry.port}
			var conn net.Conn
			if transport == "tcp" {
				conn, err = gonet.DialContextTCP(ctx, peer, target, ipv4.ProtocolNumber)
			} else {
				conn, err = gonet.DialUDP(peer, nil, &target, ipv4.ProtocolNumber)
			}
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			reply, _, exchangeErr := (&dns.Client{Net: transport}).ExchangeWithConnContext(ctx, new(dns.Msg).SetQuestion(entry.host, dns.TypeA), &dns.Conn{Conn: conn})
			conn.Close()
			cancel()
			if exchangeErr != nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || !reply.Answer[0].(*dns.A).A.Equal(localIP) {
				t.Fatal("original DNS or bound data reached the wrong network", transport, entry.host, reply, exchangeErr)
			}
		}
	}
	if queries.Load() != 2 || publications.Load() != 2 || len(r.CampusDNSRecords()) != 0 {
		t.Fatal("original DNS created campus authority or lost its capture publication", queries.Load(), publications.Load())
	}
	for _, transport := range []string{"tcp", "udp"} {
		conn, err := d.DialCapturedIPPort(t.Context(), transport, tcp.Addr().String())
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, policy.ErrProtectedTarget) {
			t.Fatal("recaptured original data escaped to a guessed interface", transport, err)
		}
	}
	if _, err := p.tun.exchangeDNS(new(dns.Msg).SetQuestion("capture.original.test.", dns.TypeA), "udp"); err != nil {
		t.Fatal(err)
	}
	if publications.Load() != 3 || slices.Contains(p.ActiveTUNAddresses(), "203.0.113.9") || len(r.OriginalDNSRecords()["capture.original.test"]) != 1 || len(r.CampusDNSRecords()) != 0 {
		t.Fatal("original publication did not hand over to the canonical binding", publications.Load())
	}
	p.tun.publishDNSRoutes = nil
	if _, err := p.tun.exchangeDNS(new(dns.Msg).SetQuestion("unpublished.original.test.", dns.TypeA), "udp"); !errors.Is(err, policy.ErrProtectedTarget) || len(r.OriginalDNSRecords()["unpublished.original.test"]) != 0 {
		t.Fatal("missing withdrawal publisher delivered or committed an original answer", err)
	}
}

func TestTUNDNSPublicationHoldJoinsOverlappingQueries(t *testing.T) {
	const host = "hold.campus.test"
	address := netip.MustParseAddr("203.0.113.9")
	r := resolve.NewResolver(nil, "", "", 60,
		client.DomainResources{host: {{Protocol: "tcp", PortMin: 80, PortMax: 80}}},
		map[string][]net.IP{host: {net.ParseIP(address.String())}}, false)
	defer r.Close()
	p := &Listeners{ctx: t.Context(), resolver: r, dialer: dial.NewDialer(nil, r, nil, false)}
	i := &tunIngress{owner: p}
	p.tun = i
	entered := make(chan struct{}, 2)
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	refused := errors.New("publication refused")
	var next atomic.Int32
	i.publishDNSRoutes = func(ctx context.Context, _ []netip.Addr, _ bool) error {
		index := int(next.Add(1)) - 1
		entered <- struct{}{}
		select {
		case <-release[index]:
			if index == 0 {
				return refused
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	completed := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := i.exchangeDNS(new(dns.Msg).SetQuestion(host+".", dns.TypeA), "udp")
			completed <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("overlapping DNS publications did not enter")
		}
	}
	checkHeld := func() {
		t.Helper()
		if got := p.ActiveTUNAddresses(); len(got) != 1 || got[0] != address.String() || len(r.CampusResourcesForIP(t.Context(), address)) != 0 {
			t.Fatal("pending capture was absent, duplicated or already authorized", got)
		}
	}
	checkHeld()
	close(release[0])
	if err := <-completed; !errors.Is(err, refused) {
		t.Fatal("publication refusal lost", err)
	}
	checkHeld()
	close(release[1])
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if got := p.ActiveTUNAddresses(); len(got) != 0 || len(r.CampusResourcesForIP(t.Context(), address)) != 1 {
		t.Fatal("publication hold did not hand over to the committed binding", got)
	}
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
	r := resolve.NewResolver(campus, "203.0.113.253", "", 30,
		client.DomainResources{"*.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, nil, true)
	t.Cleanup(r.Close)
	var protection atomic.Pointer[policy.ProtectionPolicy]
	r.ProtectionPolicy = protection.Load
	dnsResource := ingressResource("all", resolve.DNSPort)
	dnsResource.IPMin, dnsResource.IPMax = net.ParseIP("203.0.113.253"), net.ParseIP("203.0.113.253")
	d := dial.NewDialer(campus, r, []client.IPResource{dnsResource}, false)
	d.ProtectionPolicy = protection.Load
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	device := &tracedDNSDevice{dnsPacketDevice: &dnsPacketDevice{newPacketDevice()}}
	var publicationMode atomic.Int32
	publications := make(chan []netip.Addr, 16)
	release := make(chan bool)
	publicationCancelled := make(chan struct{})
	publish := func(ctx context.Context, addresses []netip.Addr, _ bool) error {
		active := p.ActiveTUNAddresses()
		for _, address := range addresses {
			if !slices.Contains(active, address.String()) {
				t.Error("pending DNS publication is missing from the capture snapshot", address)
				break
			}
		}
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
	var ownedDNS net.Conn
	t.Cleanup(func() {
		if ownedDNS != nil {
			_ = ownedDNS.Close()
		}
	})
	exchange := func(transport string, destination tcpip.FullAddress, message *dns.Msg) (*dns.Msg, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var conn net.Conn
		var err error
		if transport == "tcp" && destination == target {
			if ownedDNS == nil {
				ownedDNS, err = gonet.DialContextTCP(ctx, peer, destination, ipv4.ProtocolNumber)
			}
			conn = ownedDNS
		} else if transport == "tcp" {
			conn, err = gonet.DialContextTCP(ctx, peer, destination, ipv4.ProtocolNumber)
		} else {
			conn, err = gonet.DialUDP(peer, nil, &destination, ipv4.ProtocolNumber)
		}
		if err != nil {
			return nil, err
		}
		if conn != ownedDNS {
			defer conn.Close()
		}
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
			device.diagnose(t)
			t.Fatalf("route acknowledgement applied=%t: %v; TCP retransmits peer=%d ingress=%d, invalid peer=%d ingress=%d",
				applied, answer.err, peer.Stats().TCP.Retransmits.Value(), p.tun.stack.Stats().TCP.Retransmits.Value(),
				peer.Stats().TCP.InvalidSegmentsReceived.Value(), p.tun.stack.Stats().TCP.InvalidSegmentsReceived.Value())
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
	blocked, err := policy.NewProtectionPolicy([]string{"203.0.113.253/32"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&blocked)
	if upstream.Load() != before {
		t.Fatal("refused questions generated campus traffic")
	}
	for _, network := range []string{"tcp", "udp"} {
		if _, err := d.DialCampusIPPort(t.Context(), network, "203.0.113.253:53"); !errors.Is(err, policy.ErrProtectedTarget) {
			t.Fatal("ordinary shared endpoint was captured", err)
		}
	}
	if reply := query("tcp", target, request); reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 81 {
		t.Fatalf("internal tunnel DNS was blocked by an original address: %v", reply)
	}
	if upstream.Load() <= before || len(<-publications) != 80 {
		t.Fatal("internal DNS did not use and publish its actual tunnel answer")
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
