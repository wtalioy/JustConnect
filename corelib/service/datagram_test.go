package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestTUNUDPIdleExpiresAfterTrafficStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, sender := net.Pipe()
		right, receiver := net.Pipe()
		defer sender.Close()
		defer receiver.Close()
		done := make(chan struct{})
		go func() {
			relayDatagrams(t.Context(), left, right, 100*time.Millisecond, func(err error) { t.Error(err) })
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
	})
}

func TestTUNUDPIdleInterruptsBlockedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, sender := net.Pipe()
		right, receiver := net.Pipe()
		defer sender.Close()
		defer receiver.Close()
		const idle = 100 * time.Millisecond
		done := make(chan struct{})
		go func() {
			defer close(done)
			relayDatagrams(t.Context(), left, right, idle, func(err error) { t.Error(err) })
		}()
		if _, err := sender.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(idle - time.Nanosecond)
		select {
		case <-done:
			t.Fatal("relay closed before the idle deadline")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("idle expiry did not unblock the pending write")
		}
	})
}

type observedUDPConn struct {
	net.Conn
	operations atomic.Int32
}

func (c *observedUDPConn) Read(data []byte) (int, error) {
	c.operations.Add(1)
	return c.Conn.Read(data)
}
func (c *observedUDPConn) Write(data []byte) (int, error) {
	c.operations.Add(1)
	return c.Conn.Write(data)
}

func TestCancelledUDPRelayClosesWithoutStartingIO(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()
	defer left.Close()
	defer right.Close()
	observedLeft, observedRight := &observedUDPConn{Conn: left}, &observedUDPConn{Conn: right}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayDatagrams(ctx, observedLeft, observedRight, time.Second, func(err error) { t.Error(err) })
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled relay started blocking I/O")
	}
	if observedLeft.operations.Load() != 0 || observedRight.operations.Load() != 0 {
		t.Fatal("cancelled relay performed I/O")
	}
	for _, peer := range []net.Conn{leftPeer, rightPeer} {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatal("cancelled relay left an endpoint open", err)
		}
	}
}

func BenchmarkDatagramRelay(b *testing.B) {
	left, sender := net.Pipe()
	right, echo := net.Pipe()
	defer sender.Close()
	defer echo.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayDatagrams(b.Context(), left, right, udpIdleTimeout, func(err error) { b.Error(err) })
	}()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		var packet [1200]byte
		for {
			if _, err := io.ReadFull(echo, packet[:]); err != nil {
				return
			}
			if _, err := echo.Write(packet[:]); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() { <-done; <-echoDone })
	var packet [1200]byte
	b.ReportAllocs()
	b.SetBytes(int64(2 * len(packet)))
	for b.Loop() {
		if _, err := sender.Write(packet[:]); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(sender, packet[:]); err != nil {
			b.Fatal(err)
		}
	}
}
