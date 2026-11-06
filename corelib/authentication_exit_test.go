package corelib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

type authenticationPeer struct {
	net.Conn
	address net.Addr
}

func (c authenticationPeer) RemoteAddr() net.Addr { return c.address }

func TestOriginalAuthenticationRequiresVerifiedExternalTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := netip.MustParseAddr("192.0.2.7")
	dial := func(ctx context.Context, network, endpoint string) (net.Conn, error) {
		if network != "tcp" || endpoint != "example.com:443" {
			t.Fatalf("unexpected authentication target: %s %s", network, endpoint)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return authenticationPeer{conn, net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, 443))}, nil
	}
	external := auth.HTTPSOauth2Login{Domain: "example.com"}
	if got := originalAuthenticationOrigin(t.Context(), external, &tls.Config{RootCAs: roots}, dial); got.Address != address || got.Name != "example.com" {
		t.Fatalf("trusted original authentication peer was omitted: %v", got)
	}
	if got := originalAuthenticationOrigin(t.Context(), external, &tls.Config{InsecureSkipVerify: true}, dial); got.Address.IsValid() {
		t.Fatal("authentication bypass accepted untrusted TLS")
	}
	if got := originalAuthenticationOrigin(t.Context(), auth.PasswordLogin{Domain: "example.com"}, nil, nil); got.Address.IsValid() {
		t.Fatal("password authentication reserved an external peer")
	}
}
