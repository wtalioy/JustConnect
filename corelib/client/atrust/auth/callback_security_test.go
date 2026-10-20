package auth

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestExternalCallbacksNeverReachAnotherOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, path, query string
		call              func(*Session, string) error
	}{
		{"cas", "/passport/v1/auth/cas", "ticket=fixture", (*Session).cas},
		{"oauth2", "/passport/v1/auth/httpsOauth2", "code=fixture", (*Session).httpsOauth2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(400) }))
			defer attacker.Close()
			gateway := httptest.NewTLSServer(http.NotFoundHandler())
			defer gateway.Close()
			session := newTLSTestSession(gateway)
			defer session.Close()
			session.csrfToken = "private-fixture-token"
			if tc.call(session, attacker.URL+tc.path+"?"+tc.query) == nil {
				t.Fatal("another origin was accepted")
			}
			if requests.Load() != 0 {
				t.Fatal("callback reached another origin with session headers")
			}
		})
	}
}

func TestAuthenticationReturnURLs(t *testing.T) {
	for _, tc := range []struct{ path, token string }{
		{"/passport/v1/auth/cas", "ticket"},
		{"/passport/v1/auth/httpsOauth2", "code"},
		{"/portal/shortcut.html", "data"},
	} {
		query := "?" + tc.token + "=fixture"
		for _, raw := range []string{
			"https://VPN.EXAMPLE.INVALID" + tc.path + query,
			"https://vpn.example.invalid:443" + tc.path + query,
			"https://vpn.example.invalid:0443" + tc.path + query,
		} {
			if _, err := parseAuthCallback("https://vpn.example.invalid", raw, tc.path, tc.token); err != nil {
				t.Fatalf("same origin rejected: %v", err)
			}
		}
		for _, raw := range []string{
			"http://vpn.example.invalid" + tc.path + query,
			"https://other.example.invalid" + tc.path + query,
			"https://vpn.example.invalid:8443" + tc.path + query,
			"https://user@vpn.example.invalid" + tc.path + query,
			"https://@vpn.example.invalid" + tc.path + query,
			"https://vpn.example.invalid/other" + query,
			"https://vpn.example.invalid/%70" + tc.path[2:] + query,
			"https://vpn.example.invalid" + tc.path + query + "#fragment",
			"https://vpn.example.invalid" + tc.path + query + "#",
			"https://vpn.example.invalid" + tc.path + "?" + tc.token + "=",
			"https://vpn.example.invalid" + tc.path + "?" + tc.token + "=%20",
			"https://vpn.example.invalid" + tc.path + query + "&" + tc.token + "=second",
			"https://vpn.example.invalid" + tc.path + "?" + tc.token + "=%00",
			"https://vpn.example.invalid" + tc.path + "?" + tc.token + "=%0d%0a",
			"https://vpn.example.invalid" + tc.path + "?" + tc.token + "=%zz",
			"https://vpn.example.invalid" + tc.path + query + ";ambiguous=parameter",
			"https://vpn.example.invalid/../" + tc.path + query,
		} {
			if _, err := parseAuthCallback("https://vpn.example.invalid", raw, tc.path, tc.token); err == nil {
				t.Fatalf("unsafe return URL accepted: %q", raw)
			}
		}
		if _, err := parseAuthCallback("https://vpn.example.invalid:8443", "https://vpn.example.invalid:8443"+tc.path+query, tc.path, tc.token); err != nil {
			t.Fatal("configured custom port rejected")
		}
	}
}

func TestCallbackIPv6Origins(t *testing.T) {
	base := "https://[0:0:0:0:0:0:0:1]:8443"
	if _, err := parseAuthCallback(base, "https://[::1]:8443/passport/v1/auth/cas?ticket=fixture", "/passport/v1/auth/cas", "ticket"); err != nil {
		t.Fatal("equivalent IPv6 origin rejected")
	}
	for _, callback := range []string{"https://[::2]:8443/passport/v1/auth/cas?ticket=fixture", "https://[::1]:443/passport/v1/auth/cas?ticket=fixture"} {
		if _, err := parseAuthCallback(base, callback, "/passport/v1/auth/cas", "ticket"); err == nil {
			t.Fatal("different IPv6 origin accepted")
		}
	}
}

func TestExternalCallbacksUseConfiguredGateway(t *testing.T) {
	for _, tc := range []struct {
		path, token string
		call        func(*Session, string) error
	}{
		{"/passport/v1/auth/cas", "ticket", (*Session).cas},
		{"/passport/v1/auth/httpsOauth2", "code", (*Session).httpsOauth2},
	} {
		t.Run(tc.token, func(t *testing.T) {
			var requests atomic.Int32
			var gateway *httptest.Server
			gateway = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != tc.path || r.URL.Query().Get(tc.token) != "fixture" || r.Header.Get("x-csrf-token") != "private-fixture-token" {
					t.Error("gateway did not receive the expected authenticated callback")
				}
				http.Redirect(w, r, gateway.URL+"/portal/shortcut.html?data=%7B%22ticket%22%3A%22portal-fixture%22%7D", http.StatusFound)
			}))
			defer gateway.Close()
			session := newTLSTestSession(gateway)
			defer session.Close()
			session.csrfToken = "private-fixture-token"
			if err := tc.call(session, gateway.URL+tc.path+"?"+tc.token+"=fixture"); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || session.ticket != "portal-fixture" {
				t.Fatal("callback did not preserve the expected portal ticket")
			}
		})
	}
}
