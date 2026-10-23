package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/dial"
)

func TestCloseInterruptsIdleProxyClientsAndAllowsRebind(t *testing.T) {
	listeners, err := NewListeners(context.Background(), "127.0.0.1:0", "127.0.0.1:0", dial.NewDialer(nil, nil, nil, false), nil)
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

func TestProxyHalfClosePreservesResponseAndAllowsShutdown(t *testing.T) {
	for _, test := range []struct {
		name, protocol string
		stop           bool
	}{
		{"SOCKS/response", "socks", false},
		{"SOCKS/shutdown", "socks", true},
		{"CONNECT/response", "http", false},
		{"CONNECT/shutdown", "http", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			served := make(chan error, 1)
			requestRead := make(chan []byte, 1)
			proceed := make(chan struct{}, 1)
			defer close(proceed)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					served <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				body, err := io.ReadAll(conn)
				requestRead <- body
				if err == nil {
					<-proceed
					_, err = conn.Write(append([]byte("response:"), body...))
				}
				served <- err
			}()
			socks, http := "", ""
			if test.protocol == "socks" {
				socks = "127.0.0.1:0"
			} else {
				http = "127.0.0.1:0"
			}
			p, err := NewListeners(t.Context(), socks, http, dial.NewDialer(nil, nil, nil, false), nil)
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
			reader := bufio.NewReader(conn)
			if test.protocol == "socks" {
				if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(reader, make([]byte, 2)); err != nil {
					t.Fatal(err)
				}
				destination := target.Addr().(*net.TCPAddr)
				request := append([]byte{5, 1, 0, 1}, destination.IP.To4()...)
				request = append(request, byte(destination.Port>>8), byte(destination.Port))
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(reader, make([]byte, 10)); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(conn, "request"); err != nil {
					t.Fatal(err)
				}
			} else {
				// The first tunnel bytes may already be buffered with CONNECT headers.
				if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nrequest", target.Addr(), target.Addr()); err != nil {
					t.Fatal(err)
				}
				status, err := reader.ReadString('\n')
				if err != nil || status != "HTTP/1.1 200 Connection Established\r\n" {
					t.Fatal(status, err)
				}
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					if line == "\r\n" {
						break
					}
				}
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case request := <-requestRead:
				if string(request) != "request" {
					t.Fatalf("upstream half-close payload = %q", request)
				}
			case <-time.After(time.Second):
				t.Fatal("upstream did not observe the half-close")
			}
			// Hold the response until the proxy has proved it keeps the downstream open.
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("response arrived before release")
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("downstream closed before its response: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if test.stop {
				stopped := make(chan struct{})
				go func() { p.Close(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("shutdown hung after half-close")
				}
			}
			proceed <- struct{}{}
			if !test.stop {
				response, err := io.ReadAll(reader)
				if err != nil || string(response) != "response:request" {
					t.Fatalf("half-close response = %q, %v", response, err)
				}
			}
			select {
			case err := <-served:
				if !test.stop && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("target worker did not stop")
			}
		})
	}
}
