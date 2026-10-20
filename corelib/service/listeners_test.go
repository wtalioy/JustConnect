package service

import (
	"context"
	"io"
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

func TestSOCKSClientHalfClosePreservesDownstreamResponse(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		body, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("response:"), body...))
		}
		served <- err
	}()
	p, err := NewListeners(context.Background(), "127.0.0.1:0", "", dial.NewDialer(nil, nil, nil, false, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	conn, err := net.Dial("tcp", p.listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	destination := target.Addr().(*net.TCPAddr)
	request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
	request = append(request, byte(destination.Port>>8), byte(destination.Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "response:request" {
		t.Fatalf("half-close response = %q, %v", response, err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
