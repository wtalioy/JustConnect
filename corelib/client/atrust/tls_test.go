package atrust

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/underlay"
)

type failingTLSUnderlay struct{ err error }

func (d failingTLSUnderlay) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func (failingTLSUnderlay) ExcludeIP(net.IP) {}

func BenchmarkTunnelTLSDialFailure(b *testing.B) {
	failure := errors.New("underlay unavailable")
	c := NewClient(ClientOptions{UnderlayDialer: failingTLSUnderlay{failure}})
	defer c.Close()
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.dialTunnelTLS(ctx, "tcp", "192.0.2.2:443"); err != failure {
			b.Fatal(err)
		}
	}
}

func TestDialTLSContextUsesCallerKeyLogWriter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	dialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	var keyLog bytes.Buffer
	base := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	base.KeyLogWriter = &keyLog
	c := NewClient(ClientOptions{UnderlayDialer: dialer, TLSConfig: base})
	defer c.Close()
	if !c.tunnelTLSPolicy.SessionTicketsDisabled || c.nodeTLSPolicy.SessionTicketsDisabled || base.SessionTicketsDisabled {
		t.Fatal("only the tunnel transport should disable tickets")
	}
	conn, err := c.dialTunnelTLS(t.Context(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if base.ServerName != "" || c.tunnelTLSPolicy.ServerName != "" {
		t.Fatal("dial mutated a shared TLS server name")
	}
	if !strings.Contains(keyLog.String(), "CLIENT_") {
		t.Fatalf("key log does not contain client secrets: %q", keyLog.String())
	}
}
