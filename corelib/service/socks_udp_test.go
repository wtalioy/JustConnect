package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/dial"
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

func TestSOCKSUDPDatagramsAndActiveAssociationStop(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		buffer := make([]byte, 2048)
		for {
			n, peer, err := target.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = target.WriteToUDP(buffer[:n], peer)
		}
	}()
	defer func() { _ = target.Close(); <-served }()
	p, err := NewListeners(context.Background(), "127.0.0.1:0", "", dial.NewDialer(nil, nil, nil, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	control, err := net.Dial("tcp", p.listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting=%v, %v", greeting, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil || reply[1] != 0 {
		t.Fatalf("association=%v, %v", reply, err)
	}
	address := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	datagram, err := statute.NewDatagram(target.LocalAddr().String(), []byte("owned UDP payload"))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := client.WriteToUDP(datagram.Bytes(), address); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 2048)
		n, _, err := client.ReadFromUDP(response)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := statute.ParseDatagram(response[:n])
		if err != nil || !bytes.Equal(decoded.Data, datagram.Data) {
			t.Fatalf("datagram=%v, %v", decoded, err)
		}
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("active UDP association did not stop")
	}
	_ = control.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := control.Read(make([]byte, 1)); err == nil {
		t.Fatal("association control survived stop")
	}
	rebound, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Fatalf("association socket leaked: %v", err)
	}
	_ = rebound.Close()
}
