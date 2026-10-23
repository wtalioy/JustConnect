package bridge

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
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

func tunDatagramEcho(t *testing.T, peer *net.UDPConn, address *net.UDPAddr) {
	t.Helper()
	payload := []byte("session-owned-campus-datagram")
	packet := make([]byte, zctcpip.IPv4HeaderSize+zctcpip.UDPHeaderSize+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, zctcpip.UDP
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	ip := zctcpip.IPv4Packet(packet)
	ip.SetSourceIP(net.IPv4(198, 18, 0, 1))
	ip.SetDestinationIP(net.IPv4(192, 0, 2, 10))
	udp := zctcpip.UDPPacket(ip.Payload())
	udp.SetSourcePort(40000)
	udp.SetDestinationPort(53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp.Payload(), payload)
	udp.ResetChecksum(ip.PseudoSum())
	ip.ResetChecksum()
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
	if err := reply.Verify(); err != nil {
		t.Fatal(err)
	}
	if !reply.SourceIP().Equal(ip.DestinationIP()) || !reply.DestinationIP().Equal(ip.SourceIP()) || reply.Protocol() != zctcpip.UDP {
		t.Fatal("packet did not return from the campus tunnel")
	}
	data := zctcpip.UDPPacket(reply.Payload())
	if !data.Valid() || data.SourcePort() != udp.DestinationPort() || data.DestinationPort() != udp.SourcePort() || !bytes.Equal(data.Payload(), payload) {
		t.Fatal("campus datagram changed")
	}
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
		if status := e.AttachTUN(h, test.generation, device, test.mtu); status != test.want {
			t.Fatalf("rejected attachment=%v want %v", status, test.want)
		}
	}
	address := device.LocalAddr().(*net.UDPAddr)
	if status := e.AttachTUN(h, generation, device, 1400); status != OK {
		t.Fatal(status)
	}
	extra, extraPeer := tunDatagram(t)
	if status := e.AttachTUN(h, generation, extra, 1400); status != InvalidArgument {
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
	tunDatagramEcho(t, peer, address)
	return device
}

func TestProtocolTUNAttachDuringStop(t *testing.T) {
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
	go func() { defer workers.Done(); status = e.AttachTUN(h, ready.Generation, device, 1400) }()
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
	for _, phase := range []string{"not-ready", "device-failure"} {
		t.Run(phase, func(t *testing.T) {
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
				if status := e.AttachTUN(h, generation, fileFailureDevice{device}, 1400); status != OK {
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
				if status := e.AttachTUN(h, generation, device, 1400); status != Busy {
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
