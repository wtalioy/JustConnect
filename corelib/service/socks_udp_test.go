package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/socksudp"
)

type rejectedReply struct{ address *net.UDPAddr }

func (w *rejectedReply) Write(data []byte) (int, error) {
	if len(data) == 10 && data[3] == statute.ATYPIPv4 {
		w.address = &net.UDPAddr{IP: net.IPv4(data[4], data[5], data[6], data[7]), Port: int(binary.BigEndian.Uint16(data[8:]))}
	}
	return 0, io.ErrClosedPipe
}

func TestSOCKSUDPReplyFailureReleasesBoundSocket(t *testing.T) {
	p, err := NewListeners(context.Background(), "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	request := &socks5.Request{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, RemoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, DestAddr: &statute.AddrSpec{}}
	for range 32 {
		reply := &rejectedReply{}
		if err := p.handleSOCKSUDP(context.Background(), reply, request); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		p.mu.Lock()
		remaining := len(p.connections)
		p.mu.Unlock()
		if remaining != 0 {
			t.Fatal("failed UDP reply left a bound socket")
		}
		if reply.address == nil {
			t.Fatal("missing bound address in UDP reply")
		}
		rebound, err := net.ListenUDP("udp", reply.address)
		if err != nil {
			t.Fatalf("failed UDP reply leaked the real socket: %v", err)
		}
		_ = rebound.Close()
	}
}

type socksUDPFixture struct {
	owner   *Listeners
	control net.Conn
	client  *net.UDPConn
	address *net.UDPAddr
	targets [2]string
}

func newSOCKSUDPFixture(t testing.TB, host string, bindSource bool) socksUDPFixture {
	t.Helper()
	var targets [2]string
	for index := range targets {
		target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan struct{})
		go func() {
			defer close(served)
			buffer := make([]byte, maxUDPPacket)
			for {
				n, peer, err := target.ReadFromUDPAddrPort(buffer)
				if err != nil {
					return
				}
				_, _ = target.WriteToUDPAddrPort(buffer[:n], peer)
			}
		}()
		t.Cleanup(func() { _ = target.Close(); <-served })
		targets[index] = target.LocalAddr().String()
	}
	p, err := NewListeners(context.Background(), net.JoinHostPort(host, "0"), "", dial.NewDialer(nil, nil, nil, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	control, err := net.Dial("tcp", p.listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting=%v, %v", greeting, err)
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	port := 0
	if bindSource {
		port = client.LocalAddr().(*net.UDPAddr).Port
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port)}); err != nil {
		t.Fatal(err)
	}
	reply, err := statute.ParseReply(control)
	if err != nil || reply.Response != statute.RepSuccess {
		t.Fatalf("association=%v, %v", reply, err)
	}
	address := &net.UDPAddr{IP: reply.BndAddr.IP, Port: reply.BndAddr.Port}
	return socksUDPFixture{p, control, client, address, targets}
}

func TestSOCKSUDPDatagramsAndActiveAssociationStop(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, bindSource := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/bind=%t", host, bindSource), func(t *testing.T) {
				f := newSOCKSUDPFixture(t, host, bindSource)
				if bindSource {
					foreign, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
					if err != nil {
						t.Fatal(err)
					}
					defer foreign.Close()
					packet, err := statute.NewDatagram(f.targets[0], []byte("foreign sender"))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := foreign.WriteToUDP(packet.Bytes(), f.address); err != nil {
						t.Fatal(err)
					}
				}
				response := make([]byte, maxUDPPacket)
				for round, payload := range [][]byte{[]byte("first"), {}, bytes.Repeat([]byte("large"), 6000), []byte("last"), {}} {
					datagram, err := statute.NewDatagram(f.targets[round%len(f.targets)], payload)
					if err != nil {
						t.Fatal(err)
					}
					if round%2 == 1 {
						datagram.DstAddr.FQDN = datagram.DstAddr.IP.String()
						datagram.DstAddr.AddrType = statute.ATYPDomain
					}
					if _, err := f.client.WriteToUDP(datagram.Bytes(), f.address); err != nil {
						t.Fatal(err)
					}
					n, _, err := f.client.ReadFromUDPAddrPort(response)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := socksudp.Parse(response[:n])
					if err != nil || decoded.DstAddr.String() != datagram.DstAddr.String() || !bytes.Equal(decoded.Data, payload) {
						t.Fatalf("datagram=%v, %v", decoded, err)
					}
				}
				done := make(chan struct{})
				go func() { f.owner.Close(); close(done) }()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("active UDP association did not stop")
				}
				_ = f.control.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := f.control.Read(make([]byte, 1)); err == nil {
					t.Fatal("association control survived stop")
				}
				rebound, err := net.ListenUDP("udp", f.address)
				if err != nil {
					t.Fatalf("association socket leaked: %v", err)
				}
				_ = rebound.Close()
			})
		}
	}
}

func BenchmarkSOCKSUDPDatagrams(b *testing.B) {
	f := newSOCKSUDPFixture(b, "127.0.0.1", false)
	datagram, err := statute.NewDatagram(f.targets[0], bytes.Repeat([]byte{0x5a}, 1200))
	if err != nil {
		b.Fatal(err)
	}
	packet := datagram.Bytes()
	response := make([]byte, maxUDPPacket)
	exchange := func() {
		if _, err := f.client.WriteToUDP(packet, f.address); err != nil {
			b.Fatal(err)
		}
		n, _, err := f.client.ReadFromUDPAddrPort(response)
		if err != nil || !bytes.Equal(response[:n], packet) {
			b.Fatalf("wrong UDP reply: %d, %v", n, err)
		}
	}
	exchange()
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for b.Loop() {
		exchange()
	}
}
