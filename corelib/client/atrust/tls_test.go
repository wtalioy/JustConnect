package atrust

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

func TestDialTLSContextUsesCallerKeyLogWriter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	dialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	var keyLog bytes.Buffer
	base := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	base.KeyLogWriter = &keyLog
	config := tunnelTLSConfig(base)
	if !config.SessionTicketsDisabled || base.SessionTicketsDisabled {
		t.Fatal("tunnel transport must disable tickets without mutating caller policy")
	}
	conn, err := client.DialTLSContext(t.Context(), dialer.DialContext, "tcp", server.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if base.ServerName != "" {
		t.Fatalf("dialTLSContext mutated caller config ServerName to %q", base.ServerName)
	}
	if !strings.Contains(keyLog.String(), "CLIENT_") {
		t.Fatalf("key log does not contain client secrets: %q", keyLog.String())
	}
}
