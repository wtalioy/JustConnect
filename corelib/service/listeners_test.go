package service

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/dial"
)

func TestCloseInterruptsIdleProxyClientsAndAllowsRebind(t *testing.T) {
	listeners, err := NewListeners(context.Background(), "127.0.0.1:0", "127.0.0.1:0", dial.NewDialer(nil, nil, nil, false, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.Close()
	var clients []net.Conn
	var addresses []string
	for _, listener := range listeners.listeners {
		address := listener.Addr().String()
		addresses = append(addresses, address)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		clients = append(clients, conn)
		if _, err := conn.Write([]byte{5}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { listeners.Close(); listeners.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle proxy workers did not stop")
	}
	for _, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, err := client.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("idle client remained open")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("client was not interrupted")
		}
	}
	for _, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		_ = listener.Close()
	}
}

func TestProxyPanicReturnsFixedError(t *testing.T) {
	p, err := NewListeners(context.Background(), "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.start(func() { panic("private password") })
	select {
	case err := <-p.Errors():
		if err.Error() != "proxy worker panicked" {
			t.Fatalf("panic = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker panic not returned")
	}
	p.Close()
}

func TestProxyRejectsNonLoopbackListener(t *testing.T) {
	if p, err := NewListeners(context.Background(), "0.0.0.0:0", "", nil, nil); err == nil {
		p.Close()
		t.Fatal("public listener accepted")
	}
}
