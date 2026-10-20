package atrust

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type blockingUnderlayDialer struct{}

func (blockingUnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingUnderlayDialer) ExcludeIP(net.IP) {}

func TestSetupContextCancellationReachesManifestDial(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(ctx, SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetupContext did not cancel in-flight manifest dial")
	}
}

func TestClientCloseCancelsSetupContext(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(context.Background(), SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not cancel in-flight setup")
	}
}

func TestTunnelCloseCancelsAndJoinsConnectingWorker(t *testing.T) {
	c := NewClient(ClientOptions{})
	defer c.Close()
	c.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{client: c, conns: make(map[string]*l3TunnelConn), closeCh: make(chan struct{})}
	started, exited := make(chan struct{}), make(chan struct{})
	tunnel.connect = func(ctx context.Context, _ string, _ *conntrackMgr) (*l3TunnelConn, error) {
		close(started)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { _, err := tunnel.getConn("group"); result <- err }()
	<-started
	done := make(chan struct{})
	go func() { tunnel.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tunnel close did not join canceled connection worker")
	}
	select {
	case <-exited:
	default:
		t.Fatal("connection worker still running after Close")
	}
	if err := <-result; err == nil {
		t.Fatal("closed connection attempt succeeded")
	}
}
