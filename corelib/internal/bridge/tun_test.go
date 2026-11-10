package bridge

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func tunDatagram(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	device, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close() })
	return device, peer
}

func fixtureUDPPacket(source, destination [4]byte, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(source), DstAddr: tcpip.AddrFrom4(destination),
	})
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{SrcPort: sourcePort, DstPort: destinationPort, Length: uint16(len(udp))})
	copy(udp.Payload(), payload)
	updateFixtureUDPChecksums(ip, udp)
	return packet
}

func updateFixtureUDPChecksums(ip header.IPv4, udp header.UDP) {
	udp.SetChecksum(0)
	pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(udp)))
	udp.SetChecksum(^checksum.Checksum(udp, pseudo))
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
}

func exchangeProtocolTUN(t *testing.T, peer *net.UDPConn, address *net.UDPAddr, payload []byte) []byte {
	t.Helper()
	packet := fixtureUDPPacket([4]byte{198, 18, 0, 1}, [4]byte{192, 0, 2, 10}, 40000, 53, payload)
	ip := zctcpip.IPv4Packet(packet)
	udp := zctcpip.UDPPacket(ip.Payload())
	if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(packet, address); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1400)
	n, _, err := peer.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	reply := zctcpip.IPv4Packet(response[:n])
	if !reply.Valid() || !header.IPv4(reply).IsChecksumValid() {
		t.Fatal("invalid IPv4 reply or checksum")
	}
	if !reply.SourceIP().Equal(ip.DestinationIP()) || !reply.DestinationIP().Equal(ip.SourceIP()) || reply.Protocol() != zctcpip.UDP {
		t.Fatal("packet did not return from the campus tunnel")
	}
	data := zctcpip.UDPPacket(reply.Payload())
	if !data.Valid() || data.SourcePort() != udp.DestinationPort() || data.DestinationPort() != udp.SourcePort() {
		t.Fatal("campus datagram changed")
	}
	return data.Payload()
}

func exerciseProtocolTUN(t *testing.T, e *Engine, h, generation uint64) *net.UDPConn {
	t.Helper()
	device, peer := tunDatagram(t)
	for _, test := range []struct {
		generation uint64
		mtu        uint32
		want       Status
	}{
		{0, 1400, InvalidArgument}, {generation + 1, 1400, StaleRequest}, {generation, 1, InvalidArgument},
	} {
		if status := e.AttachTUN(h, test.generation, device, test.mtu, false); status != test.want {
			t.Fatalf("rejected attachment=%v want %v", status, test.want)
		}
	}
	address := device.LocalAddr().(*net.UDPAddr)
	if status := e.AttachTUN(h, generation, device, 1400, false); status != OK {
		t.Fatal(status)
	}
	extra, extraPeer := tunDatagram(t)
	if status := e.AttachTUN(h, generation, extra, 1400, false); status != InvalidArgument {
		t.Fatal(status)
	}
	if _, err := extra.Write([]byte("caller-owned")); err != nil {
		t.Fatal("rejected device was closed", err)
	}
	_ = extraPeer.SetReadDeadline(time.Now().Add(time.Second))
	marker := make([]byte, 64)
	if n, _, err := extraPeer.ReadFromUDP(marker); err != nil || string(marker[:n]) != "caller-owned" {
		t.Fatalf("rejected device ownership: %q %v", marker[:n], err)
	}
	payload := []byte("session-owned-campus-datagram")
	if !bytes.Equal(exchangeProtocolTUN(t, peer, address, payload), payload) {
		t.Fatal("campus datagram payload changed")
	}
	return device
}

func TestProtocolTUNAttachDuringStop(t *testing.T) {
	t.Parallel()
	g := newGateway(t)
	e := New(RunProtocol)
	h := create(t, e)
	startProtocol(t, e, h, g.config(t))
	ready := next(t, e, h)
	if ready.State != "ready" {
		t.Fatal(ready)
	}
	device, _ := tunDatagram(t)
	var workers sync.WaitGroup
	workers.Add(1)
	var status Status
	go func() { defer workers.Done(); status = e.AttachTUN(h, ready.Generation, device, 1400, false) }()
	if e.Stop(h, 3000) != OK {
		t.Fatal("stop did not join concurrent attachment")
	}
	workers.Wait()
	if status != OK && status != StaleRequest {
		t.Fatal(status)
	}
	if status == OK {
		if _, err := device.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("concurrent attachment escaped session cleanup", err)
		}
	} else if _, err := device.Write([]byte("still-caller-owned")); err != nil {
		t.Fatal("failed attachment consumed the device", err)
	}
	if terminal := next(t, e, h); terminal.Type != "terminal" || terminal.Status != Cancelled {
		t.Fatal(terminal)
	}
}

type fileFailureDevice struct{ *net.UDPConn }

func (d fileFailureDevice) Read(packet []byte) (int, error) {
	n, err := d.UDPConn.Read(packet)
	if err != nil {
		err = &os.PathError{Op: "read", Path: "owned-tun", Err: syscall.EIO}
	}
	return n, err
}

func TestProtocolTUNReadinessAndDeviceFailure(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"not-ready", "device-failure"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			active := phase == "device-failure"
			g := newGateway(t)
			g.pauseIP.Store(!active)
			e := New(RunProtocol)
			h := create(t, e)
			generation, status := e.Start(h, configBytes(t, g.config(t)))
			if status != OK {
				t.Fatal(status)
			}
			next(t, e, h)
			authenticate(t, e, h)
			device, _ := tunDatagram(t)
			expected := NetworkFailure
			if active {
				if ready := next(t, e, h); ready.State != "ready" {
					t.Fatal(ready)
				}
				if status := e.AttachTUN(h, generation, fileFailureDevice{device}, 1400, false); status != OK {
					t.Fatal(status)
				}
				if err := device.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				select {
				case <-g.ipStarted:
				case <-time.After(5 * time.Second):
					t.Fatal("IP setup did not start")
				}
				if status := e.AttachTUN(h, generation, device, 1400, false); status != Busy {
					t.Fatal(status)
				}
				if e.Stop(h, 3000) != OK {
					t.Fatal("not-ready session did not stop")
				}
				if _, err := device.Write([]byte("still-caller-owned")); err != nil {
					t.Fatal("not-ready attachment consumed device", err)
				}
				expected = Cancelled
			}
			if terminal := next(t, e, h); terminal.Type != "terminal" || terminal.Status != expected {
				t.Fatal(terminal)
			}
			if e.Stop(h, 3000) != OK {
				t.Fatal("failed session retained resources")
			}
		})
	}
}

func TestProtocolDNSCanonicalFollowup(t *testing.T) {
	g := newGateway(t)
	g.resourceIP.Store("192.0.2.10")
	g.nativeDNS.Store(true)
	g.probeDNS.Store(true)
	engine := New(RunProtocol)
	handle := create(t, engine)
	startProtocol(t, engine, handle, g.config(t))
	ready := next(t, engine, handle)
	if ready.State != "ready" {
		t.Fatal(ready)
	}
	device, peer := tunDatagram(t)
	if status := engine.AttachTUN(handle, ready.Generation, device, 1400, false); status != OK {
		t.Fatal(status)
	}
	query := func(name string, kind uint16) *dns.Msg {
		t.Helper()
		request := new(dns.Msg).SetQuestion(name, kind)
		wire, err := request.Pack()
		if err != nil {
			t.Fatal(err)
		}
		response := new(dns.Msg)
		err = response.Unpack(exchangeProtocolTUN(t, peer, device.LocalAddr().(*net.UDPAddr), wire))
		if err != nil || response.Id != request.Id || response.Rcode != dns.RcodeSuccess {
			t.Fatalf("DNS exchange %s/%d: %v, %v", name, kind, response, err)
		}
		return response
	}
	original := query("campus.test.", dns.TypeA)
	if len(original.Answer) != 2 {
		t.Fatal("missing campus CNAME and address", original)
	}
	canonical, ok := original.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatal("missing CNAME", original)
	}
	answer := query(canonical.Target, dns.TypeA)
	if len(answer.Answer) != 1 || answer.Answer[0].String() != original.Answer[1].String() {
		t.Fatal("canonical follow-up lost its advertised address", answer)
	}
	if answer := query(canonical.Target, dns.TypeAAAA); len(answer.Answer) != 0 {
		t.Fatal("IPv4-only name invented an IPv6 address", answer)
	}
	if engine.Stop(handle, 3000) != OK {
		t.Fatal("DNS session failed to stop")
	}
}
