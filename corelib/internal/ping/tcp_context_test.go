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

func TestProbeStartsImmediatelyAndWaitsOnlyBetweenAttempts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	policy := server.Client().Transport.(*http.Transport).TLSClientConfig
	target := Target{Address: server.Listener.Addr().String(), Counter: 1, Interval: time.Hour, Timeout: time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := Probe(ctx, target, nil, policy)
	if result.Counter != 1 || result.SuccessCounter != 1 || result.Err != nil {
		t.Fatalf("first TLS probe waited for the interval: %+v", result)
	}

	ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	target.Counter = 3
	attempts := 0
	result = Probe(ctx, target, func(context.Context, string, string) (net.Conn, error) {
		attempts++
		return nil, errors.New("unreachable node")
	}, policy)
	if result.Counter != 1 || attempts != 1 || result.SuccessCounter != 0 {
		t.Fatalf("probe did not wait between attempts or stop on cancellation: attempts=%d, result=%+v", attempts, result)
	}

	result = Probe(ctx, target, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("cancelled probe started a dial")
		return nil, nil
	}, policy)
	if result.Counter != 0 {
		t.Fatalf("cancelled probe counted an attempt: %+v", result)
	}
}

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

func TestSingleCandidateStopsOnlyAfterSuccessfulTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	policy := server.Client().Transport.(*http.Transport).TLSClientConfig
	attempts := 0
	result := Probe(t.Context(), Target{Address: server.Listener.Addr().String(), Counter: 3,
		Interval: time.Millisecond, Timeout: time.Second, StopOnSuccess: true}, func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("transient dial failure")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}, policy)
	if attempts != 2 || result.Counter != 2 || result.SuccessCounter != 1 || result.Err != nil {
		t.Fatalf("single candidate did not retry until its first valid TLS connection: attempts=%d result=%+v", attempts, result)
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
