package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSRequiresExplicitTrustAndKeepsCallerPolicy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	trusted := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	wrongHost := trusted.Clone()
	wrongHost.ServerName = "wrong.invalid"
	for _, test := range []struct {
		name       string
		policy     *tls.Config
		trustError bool
	}{
		{"default", nil, true}, {"private CA", trusted, false}, {"wrong hostname", wrongHost, true},
		{"explicit unsafe policy", &tls.Config{InsecureSkipVerify: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := DialTLSContext(t.Context(), (&net.Dialer{}).DialContext, "tcp", server.Listener.Addr().String(), test.policy)
			if conn != nil {
				defer conn.Close()
			}
			var verification *tls.CertificateVerificationError
			if test.trustError {
				if !errors.As(err, &verification) {
					t.Fatalf("expected certificate failure, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	if trusted.ServerName != "" || trusted.InsecureSkipVerify {
		t.Fatal("mutated caller trust policy")
	}
}

func TestTLSHandshakeCancellationAndTimeoutCloseTransport(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "timeout"}[timeout], func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			var ctx context.Context
			var cancel context.CancelFunc
			if timeout {
				ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			started := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := DialTLSContext(ctx, func(context.Context, string, string) (net.Conn, error) { close(started); return local, nil }, "tcp", "example.com:443", nil)
				done <- err
			}()
			<-started
			if !timeout {
				cancel()
			}
			select {
			case err := <-done:
				want := context.Canceled
				if timeout {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("handshake did not finish")
			}
			if _, err := local.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("transport not closed")
			}
		})
	}
}
