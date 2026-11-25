package atrust

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type blockingUnderlayDialer struct{ started chan<- struct{} }

func (d blockingUnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingUnderlayDialer) ExcludeIP(net.IP) {}

func TestSetupCancellationReachesManifestDial(t *testing.T) {
	for _, name := range []string{"caller-cancels", "client-closes"} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{}, 1)
			client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{started: started}})
			defer client.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := client.SetupContext(ctx, SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
				done <- err
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("setup ended before dialing the manifest: %v", err)
			case <-time.After(time.Second):
				t.Fatal("setup did not reach the manifest dial")
			}
			if name == "caller-cancels" {
				cancel()
			} else {
				client.Close()
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("in-flight manifest dial did not cancel")
			}
		})
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
