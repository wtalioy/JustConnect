package bridge

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestSetupFailureDiagnostics(t *testing.T) {
	for _, tt := range []struct {
		name  string
		stage string
	}{
		{"cached_manifest_restore_failed", "setup_restore_failed"},
		{"resource_http_error", "setup_resources_failed"},
		{"resource_application_error", "setup_resources_failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := newGateway(t)
			e := New(RunProtocol)
			h := create(t, e)
			c := g.config(t)
			c.LocalProxy = true
			c.Listeners.SOCKS = freeAddress(t)
			want := []string{tt.stage}
			if tt.name == "cached_manifest_restore_failed" {
				g.resumeCookies.Store(true)
				cache, _, _, err := setupWithCache(t, g, nil)
				if err != nil {
					t.Fatal(err)
				}
				c.Auth.AuthID, c.Auth.SubType = "fixture-primary", "sms"
				c.Auth.Phone = "86-123456"
				c.AuthenticationCache.Enabled = true
				c.AuthenticationCache.Account = "fixture-user"
				c.AuthenticationCache.Data = cache
				g.manifestFails.Store(true)
				g.authConfigFails.Store(true)
				want = append([]string{"manifest_cached"}, want...)
				if _, status := e.Start(h, configBytes(t, c)); status != OK {
					t.Fatal(status)
				}
			} else {
				if tt.name == "resource_http_error" {
					g.resourceHTTP.Store(http.StatusServiceUnavailable)
				} else {
					g.resourceCode.Store(42)
				}
				startProtocol(t, e, h, c)
			}
			var codes []string
			for {
				data, _, status := e.Read(h, MaxOutput, 5000)
				var ev event
				if status != OK || json.Unmarshal(data, &ev) != nil || strings.Contains(string(data), "private-") {
					t.Fatalf("invalid setup event: %s (%v)", data, status)
				}
				if ev.Type == "diagnostic" && (ev.Code == "manifest_cached" || strings.HasPrefix(ev.Code, "setup_")) {
					codes = append(codes, ev.Code)
				}
				if ev.State == "ready" || ev.Type == "authentication" || ev.Type == "authentication_cache" {
					t.Fatalf("unexpected event after failed setup: %s/%s", ev.Type, ev.State)
				}
				if ev.Type == "terminal" {
					if ev.Status != Internal || !slices.Equal(codes, want) {
						t.Fatalf("terminal status = %v, diagnostics = %v; want Internal and %v", ev.Status, codes, want)
					}
					break
				}
			}
		})
	}
}
