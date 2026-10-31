//go:build darwin

package bridge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNativeMacCoexistence(t *testing.T) {
	input := os.Getenv("JC_NATIVE_MAC_COEXISTENCE")
	if input == "" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("requires the disposable macOS root runtime and actual authorized network fixture")
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(input), &facts); err != nil {
		t.Fatal(err)
	}
	protected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("original-http")) }))
	t.Cleanup(protected.Close)
	facts["protected_url"] = protected.URL
	data, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JC_NATIVE_MAC_COEXISTENCE", string(data))
	g, output := runNativeTUNHost(t, false)
	const cases = 24
	if bytes.Count(output, []byte("PASS: macOS composed coexistence case ")) != cases ||
		g.authCount.Load() != 2 || g.tcpCount.Load() != 6+4*cases ||
		g.sshCount.Load() != 4+2*cases || g.udpCount.Load() != 4+2*cases+g.nativeDNSQueries.Load() || g.nativeDNSQueries.Load() < 2 {
		t.Fatalf("missing real macOS matrix traffic: auth=%d TCP=%d SSH=%d UDP=%d DNS=%d\n%s", g.authCount.Load(),
			g.tcpCount.Load(), g.sshCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	t.Log(string(output))
}
