package mihomo

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

func TestConfigurationOverridesAndLocalEndpointBoundary(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "config.yaml"), []byte("external-controller: localhost:49153\nsecret: configured-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := model.Process{Directory: directory, Args: []string{"mihomo", "-d", ".", "-secret=actual-override"}}
	list, err := endpoints(p)
	if err != nil || len(list) != 2 || list[0].secret != "actual-override" || list[0].address != "127.0.0.1:49153" || list[1].address != "[::1]:49153" {
		t.Fatalf("relative configuration and actual overrides: %+v %v", list, err)
	}
	for _, address := range []string{"192.0.2.10:49153", "remote.example.test:49153", "127.0.0.1:0", "127.0.0.1:65536"} {
		p.Args = []string{"mihomo", "-f", "config.yaml", "-ext-ctl", address}
		if _, err = endpoints(p); err == nil {
			t.Fatal("accepted a non-local or invalid controller", address)
		}
	}
	if model.ListenerMatches(netip.IPv6Unspecified(), netip.MustParseAddr("127.0.0.1")) || !model.ListenerMatches(netip.IPv4Unspecified(), netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("native listener ownership crossed address families")
	}
}

func TestControllerTLSRetainsLogicalIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"verified":true}`))
	}))
	defer server.Close()
	originalValid, originalOwns := validProcess, ownsTCP
	t.Cleanup(func() { validProcess, ownsTCP = originalValid, originalOwns })
	validProcess = func(model.Process) bool { return true }
	ownsTCP = func(context.Context, model.Process, netip.AddrPort) bool { return true }
	for _, name := range []string{"example.com", "wrong.example.test"} {
		client := newClient(endpoint{network: "tcp", address: server.Listener.Addr().String(), scheme: "https", serverName: name})
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
		var response map[string]bool
		err := client.read(t.Context(), "/", nil, &response)
		client.Close()
		if (err == nil) != (name == "example.com") || err == nil && !response["verified"] {
			t.Fatalf("logical controller certificate validation %q: %v", name, err)
		}
	}
}
