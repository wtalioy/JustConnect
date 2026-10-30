package ping

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeCancellationInterruptsBlockedDial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	dialCancelled := make(chan error, 1)
	done := make(chan Result, 1)
	go func() {
		done <- Probe(ctx, Target{Address: "node.example.test:443", Counter: 3, Interval: time.Millisecond, Timeout: time.Minute},
			func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				dialCancelled <- ctx.Err()
				return nil, ctx.Err()
			}, nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe never started its dial")
	}
	cancel()
	select {
	case result := <-done:
		if result.Counter != 0 || result.SuccessCounter != 0 {
			t.Fatalf("cancelled probe result = %+v, want no completed attempt", result)
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not stop after context cancellation")
	}
	if err := <-dialCancelled; !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want cancellation", err)
	}
}

func TestProbePreservesAttemptsAndPartialSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	policy := server.Client().Transport.(*http.Transport).TLSClientConfig
	unreachable := errors.New("unreachable node")
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreachable", true: "partial success"}[success], func(t *testing.T) {
			attempts := 0
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				attempts++
				if success && attempts == 2 {
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				return nil, unreachable
			}
			result := Probe(t.Context(), Target{Address: server.Listener.Addr().String(), Counter: 3, Interval: time.Millisecond, Timeout: time.Second}, dial, policy)
			if result.Counter != 3 || attempts != 3 {
				t.Fatalf("attempts = %d, result = %+v", attempts, result)
			}
			if success {
				if result.Err != nil || result.SuccessCounter != 1 || result.TotalDuration <= 0 {
					t.Fatalf("partial success lost: %+v", result)
				}
			} else if !errors.Is(result.Err, unreachable) || result.SuccessCounter != 0 || result.TotalDuration != 0 {
				t.Fatalf("unreachable result = %+v", result)
			}
		})
	}
}

func TestProbeCancellationInterruptsTLSHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	go func() {
		var hello [1]byte
		if _, err := peer.Read(hello[:]); err == nil {
			close(started)
		}
	}()
	done := make(chan Result, 1)
	go func() {
		done <- Probe(ctx, Target{Address: "node.example.test:443", Counter: 3, Interval: time.Millisecond, Timeout: time.Minute},
			func(context.Context, string, string) (net.Conn, error) {
				return client, nil
			}, &tls.Config{})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake did not start")
	}
	cancel()
	select {
	case result := <-done:
		if result.Counter != 0 {
			t.Fatalf("cancelled handshake counted: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake ignored cancellation")
	}
}
