package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	campusstack "github.com/wtalioy/JustConnect/corelib/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type packetDevice struct {
	input, output chan []byte
	closed        chan struct{}
	once          sync.Once
	dropOutput    bool
	dropTCPData   chan struct{}
}

func newPacketDevice() *packetDevice {
	return &packetDevice{input: make(chan []byte, 32), output: make(chan []byte, 32), closed: make(chan struct{})}
}
func (d *packetDevice) Read(b []byte) (int, error) {
	select {
	case data := <-d.input:
		return copy(b, data), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}
func (d *packetDevice) Write(b []byte) (int, error) {
	if d.dropOutput {
		return len(b), nil
	}
	if d.dropTCPData != nil && len(b) >= header.IPv4MinimumSize && header.IPv4(b).TransportProtocol() == tcp.ProtocolNumber {
		segment := header.TCP(header.IPv4(b).Payload())
		if len(segment.Payload()) > 0 {
			select {
			case d.dropTCPData <- struct{}{}:
				return len(b), nil
			default:
			}
		}
	}
	select {
	case d.output <- bytes.Clone(b):
		return len(b), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}
func (d *packetDevice) Close() error { d.once.Do(func() { close(d.closed) }); return nil }

func tunPeer(t *testing.T, device *packetDevice) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(32, 1400, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	address := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), PrefixLen: 32}}
	if err := s.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := bytes.Clone(view.AsSlice())
			view.Release()
			packet.DecRef()
			select {
			case device.input <- data:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case data := <-device.output:
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
				link.InjectInbound(ipv4.ProtocolNumber, packet)
				packet.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() { cancel(); link.Close(); workers.Wait(); s.Close(); s.Wait() })
	return s
}

type ingressCampus struct {
	tcpAddress, udpAddress string
	called                 chan string
}

func (s *ingressCampus) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	s.called <- "tcp:" + addr.String()
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.tcpAddress)
}
func (s *ingressCampus) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	s.called <- "udp:" + addr.String()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", s.udpAddress)
	if err != nil {
		return nil, err
	}
	// The native fixture must accept the full datagram contract, including macOS.
	if err := conn.(*net.UDPConn).SetWriteBuffer(maxUDPPacket); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func newIngressOwner(t *testing.T, campus campusstack.Stack, protection *policy.ProtectionPolicy, resources []client.IPResource) (*Listeners, *packetDevice) {
	t.Helper()
	d := dial.NewDialer(campus, nil, resources, false)
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return protection }
	p, err := NewListeners(t.Context(), "", "", d, nil)
	if err != nil {
		t.Fatal(err)
	}
	device := newPacketDevice()
	if err := p.AttachTUN(device, 1400, nil); err != nil {
		p.Close()
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, device
}

func ingressResource(protocol string, port int) client.IPResource {
	ip := net.IPv4(203, 0, 113, 7)
	return client.IPResource{IPMin: ip, IPMax: ip, PortMin: port, PortMax: port, Protocol: protocol}
}

func closeIngress(t *testing.T, p *Listeners) {
	t.Helper()
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
		t.Fatal("TUN shutdown did not interrupt and join its workers")
	}
}

func TestTUNRelaysTCPHalfCloseAndUDPDatagrams(t *testing.T) {
	// macOS ARM64 race runs take several seconds to recover the deliberately lost segment.
	const networkTimeout = 30 * time.Second
	tcpTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpTarget.Close()
	responseReady := make(chan struct{})
	requestRead := make(chan struct{})
	served := make(chan error, 1)
	defer close(responseReady)
	go func() {
		conn, err := tcpTarget.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(networkTimeout))
		data, err := io.ReadAll(conn)
		if err != nil {
			served <- err
			return
		}
		close(requestRead)
		<-responseReady
		_ = conn.SetWriteDeadline(time.Now().Add(networkTimeout))
		written, err := conn.Write(append([]byte("reply:"), data...))
		if err != nil {
			err = fmt.Errorf("target wrote %d bytes: %w", written, err)
		}
		served <- err
	}()
	udpTarget, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	if err := udpTarget.SetWriteBuffer(maxUDPPacket); err != nil {
		t.Fatal(err)
	}
	udpErrors := make(chan error, 1)
	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			n, peer, err := udpTarget.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udpTarget.WriteTo(buf[:n], peer); err != nil {
				udpErrors <- err
				return
			}
		}
	}()
	campus := &ingressCampus{tcpTarget.Addr().String(), udpTarget.LocalAddr().String(), make(chan string, 8)}
	p, device := newIngressOwner(t, campus, nil, []client.IPResource{ingressResource("tcp", 80), ingressResource("udp", 53)})
	device.dropTCPData = make(chan struct{}, 1)
	peer := tunPeer(t, device)
	ctx, cancel := context.WithTimeout(t.Context(), networkTimeout)
	defer cancel()
	destination := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: 80}
	conn, err := gonet.DialContextTCP(ctx, peer, destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(networkTimeout))
	payload := bytes.Repeat([]byte("request"), 1<<14)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestRead:
	case err := <-served:
		t.Fatalf("TCP target failed before request EOF: %v", err)
	case <-ctx.Done():
		t.Fatal("target did not receive TCP EOF")
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected response before target release")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("half-close discarded response: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(networkTimeout))
	responseReady <- struct{}{}
	if data, err := io.ReadAll(conn); err != nil || !bytes.Equal(data, append([]byte("reply:"), payload...)) {
		t.Fatalf("TCP reply=%d bytes, %v", len(data), err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	select {
	case <-device.dropTCPData:
	default:
		t.Fatal("TCP retransmission scenario did not drop a data segment")
	}
	destination.Port = 53
	udpConn, err := gonet.DialUDP(peer, nil, &destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(networkTimeout))
	for _, data := range [][]byte{[]byte("first"), {}, bytes.Repeat([]byte("large"), 4000), []byte("last")} {
		if _, err := udpConn.Write(data); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, maxUDPPacket)
		n, err := udpConn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], data) {
			select {
			case targetErr := <-udpErrors:
				t.Fatalf("UDP fixture reply failed: %v", targetErr)
			default:
			}
			t.Fatalf("UDP datagram %d bytes -> %d bytes: %v", len(data), n, err)
		}
	}
	for _, want := range []string{"tcp:203.0.113.7:80", "udp:203.0.113.7:53"} {
		select {
		case got := <-campus.called:
			if got != want {
				t.Fatalf("campus target=%s, want %s", got, want)
			}
		default:
			t.Fatal("campus not used")
		}
	}
	closeIngress(t, p)
	_ = udpConn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := udpConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stopped TUN returned UDP data")
	}
}

func TestTUNRejectsUnownedAttachmentAndCapturedFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		protect bool
		port    uint16
	}{
		{"unauthorized", false, 81}, {"protected", true, 80},
	} {
		t.Run(test.name, func(t *testing.T) {
			var protection *policy.ProtectionPolicy
			if test.protect {
				value, err := policy.NewProtectionPolicy([]string{"203.0.113.0/24"}, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				protection = &value
			}
			campus := &ingressCampus{called: make(chan string, 1)}
			p, device := newIngressOwner(t, campus, protection, []client.IPResource{ingressResource("tcp", 80)})
			unused := newPacketDevice()
			defer unused.Close()
			if err := p.AttachTUN(unused, 1400, nil); err == nil {
				t.Fatal("second device accepted")
			}
			select {
			case <-unused.closed:
				t.Fatal("failed attachment took device ownership")
			default:
			}
			peer := tunPeer(t, device)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: test.port}, ipv4.ProtocolNumber)
			if err == nil {
				conn.Close()
				t.Fatal("denied captured TCP connected")
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("denied flow was not reset promptly")
			}
			select {
			case got := <-campus.called:
				t.Fatal("denied flow reached campus", got)
			default:
			}
			closeIngress(t, p)
			if err := p.AttachTUN(unused, 1400, nil); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("attachment after close=%v", err)
			}
		})
	}
}

func TestTUNShutdownAbortsIncompleteHandshakeAndDeviceFailure(t *testing.T) {
	for _, failDevice := range []bool{false, true} {
		t.Run(fmt.Sprint(failDevice), func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			campus := &ingressCampus{tcpAddress: target.Addr().String(), called: make(chan string, 1)}
			p, device := newIngressOwner(t, campus, nil, []client.IPResource{ingressResource("tcp", 80)})
			device.dropOutput = true
			peer := tunPeer(t, device)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			dialDone := make(chan struct{})
			go func() {
				conn, _ := gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: 80}, ipv4.ProtocolNumber)
				if conn != nil {
					conn.Close()
				}
				close(dialDone)
			}()
			select {
			case <-campus.called:
			case <-time.After(time.Second):
				t.Fatal("TCP handshake did not start")
			}
			if failDevice {
				_ = device.Close()
				select {
				case <-p.Errors():
				case <-time.After(time.Second):
					t.Fatal("device failure did not reach session owner")
				}
			}
			closeIngress(t, p)
			cancel()
			select {
			case <-dialDone:
			case <-time.After(time.Second):
				t.Fatal("peer dial did not cancel")
			}
		})
	}
}

func TestTUNUDPIdleExpiresAfterTrafficStops(t *testing.T) {
	left, sender := net.Pipe()
	right, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	done := make(chan struct{})
	go func() {
		relayDatagrams(left, right, 100*time.Millisecond, func(err error) { t.Error(err) })
		close(done)
	}()
	for range 4 {
		if err := sender.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		written := make(chan error, 1)
		go func() { _, err := sender.Write([]byte("one-way")); written <- err }()
		data := make([]byte, 7)
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(receiver, data); err != nil || string(data) != "one-way" {
			t.Fatalf("active one-way UDP expired: %q, %v", data, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle UDP relay retained both endpoints")
	}
}

type capacityCampus struct {
	ingressCampus
	mu    sync.Mutex
	peers []net.Conn
}

func (s *capacityCampus) DialUDP(_ context.Context, addr *net.UDPAddr) (net.Conn, error) {
	conn, peer := net.Pipe()
	s.mu.Lock()
	s.peers = append(s.peers, peer)
	s.mu.Unlock()
	s.called <- "udp:" + addr.String()
	return conn, nil
}

func TestTUNBoundsFlowsAndJoinsFullCapacityOnShutdown(t *testing.T) {
	// Capacity and joining must not depend on the host's socket descriptor limit.
	campus := &capacityCampus{ingressCampus: ingressCampus{called: make(chan string, maxTUNFlows+1)}}
	defer func() {
		campus.mu.Lock()
		defer campus.mu.Unlock()
		for _, peer := range campus.peers {
			_ = peer.Close()
		}
	}()
	p, device := newIngressOwner(t, campus, nil, []client.IPResource{ingressResource("udp", 53)})
	peer := tunPeer(t, device)
	destination := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: 53}
	for n := 0; n <= maxTUNFlows; n++ {
		conn, err := gonet.DialUDP(peer, nil, &destination, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("idle flow")); err != nil {
			t.Fatal(err)
		}
		if n < maxTUNFlows {
			select {
			case <-campus.called:
			case <-time.After(time.Second):
				t.Fatalf("flow %d failed to start", n)
			}
		}
	}
	select {
	case <-campus.called:
		t.Fatal("TUN exceeded its active flow limit")
	case <-time.After(30 * time.Millisecond):
	}
	closeIngress(t, p)
}
