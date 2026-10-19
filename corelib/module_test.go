package corelib

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

func TestIntegratedATrustGateway(t *testing.T) {
	const manifest = `{"code":0,"data":{"capacities":{"zeroRTT":{"version":"1.0"}},"options":{"tun0rtt":{"enable":true}}}}`
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"manifest", http.StatusOK, manifest},
		{"gateway failure", http.StatusBadGateway, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/public/manifest" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := auth.NewSessionContext(ctx, "vpn.example.invalid:443", nil,
				func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != "vpn.example.invalid:443" {
						return nil, fmt.Errorf("unexpected dial: %s", address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				})
			body, err := session.ServerVersionInfo()
			if test.status != http.StatusOK {
				if err == nil || !strings.Contains(err.Error(), "HTTP status 502") {
					t.Fatalf("gateway error = %v", err)
				}
				return
			}
			if err != nil || string(body) != manifest {
				t.Fatalf("manifest = %q, error = %v", body, err)
			}
		})
	}
}
