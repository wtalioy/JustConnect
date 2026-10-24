package bridge

import (
	"context"
	"errors"
	"net/http"
	"os"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func TestOnlineMaintenanceAndIdleTrafficControls(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		disableDNS bool
	}{{"off", "off", false}, {"auto", "auto", false}, {"target", "target", false}, {"disabled_dns", "auto", true}} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			g := newGateway(t)
			g.resumeCookies.Store(true)
			g.probeDNS.Store(true)
			config := g.config(t)
			observations := make(chan [2]string, 1024)
			invalidated := make(chan struct{})
			var invalidations, saves atomic.Int32
			options := corelib.Options{
				Client: atrust.ClientOptions{UnderlayDialer: &cacheDialer{}, TLSConfig: g.HTTP.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
					Observe: func(stage, result string) { observations <- [2]string{stage, result} }},
				Setup: atrust.SetupOptions{ServerAddress: config.Server.Host, ServerPort: int(config.Server.Port), AuthID: "fixture-primary", AuthSubType: "sms",
					LoginMethod: auth.SMSLogin{Phone: "fixture-phone", Domain: "fixture"}, SessionRefreshInterval: 15 * time.Millisecond, BestNodesRefreshInterval: time.Hour,
					ChallengeHandler: authchallenge.HandlerFuncs{Code: func(authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
						return authchallenge.CodeResponse{Code: "fixture-code"}, nil
					}},
					SaveClientData: func([]byte) error { saves.Add(1); return nil }, ClientDataInvalidated: func() { invalidations.Add(1); close(invalidated) }},
				KeepAliveMode: mode, KeepAliveURL: "http://campus.test/repeatable", DisableRemoteDNS: test.disableDNS,
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			ready := make(chan struct{})
			go func() {
				done <- corelib.NewSession(options).Run(ctx, corelib.Observer{Ready: func() error { close(ready); return nil }})
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatal("session did not become ready", err)
			case <-time.After(5 * time.Second):
				t.Fatal("session startup timed out")
			}
			observationTimeout := corelib.TrafficProbeTimeout + 3*time.Second
			wait := func(stage, result string) {
				t.Helper()
				// A renewal follows the preceding traffic probe on the same worker.
				deadline := time.NewTimer(observationTimeout)
				defer deadline.Stop()
				for {
					select {
					case observation := <-observations:
						if observation == [2]string{stage, result} {
							return
						}
					case err := <-done:
						t.Fatal("maintenance ended prematurely", err)
					case <-deadline.C:
						t.Fatalf("no %s/%s observation", stage, result)
					}
				}
			}
			wait("renewal", "succeeded")
			wait("renewal", "succeeded")
			if mode == "off" || test.disableDNS {
				if g.tcpCount.Load() != 0 || g.udpCount.Load() != 0 {
					t.Fatal("disabled traffic probes or DNS sent application traffic")
				}
				if test.disableDNS {
					wait("traffic", "unavailable")
				}
			} else {
				wait("traffic", "succeeded")
				if mode == "auto" && (g.udpCount.Load() == 0 || g.tcpCount.Load() != 0) {
					t.Fatal("automatic DNS probe used the wrong path")
				}
				if mode == "target" && (g.tcpCount.Load() == 0 || g.udpCount.Load() != 0) {
					t.Fatal("target HTTP probe used the wrong path")
				}
			}
			g.authConfigFails.Store(true)
			wait("renewal", "failed")
			if invalidations.Load() != 0 || g.authCount.Load() != 1 {
				t.Fatal("transient renewal failure invalidated authentication or replayed login")
			}
			g.authConfigFails.Store(false)
			wait("renewal", "succeeded")
			g.expireCookies.Store(true)
			select {
			case <-invalidated:
			case <-time.After(observationTimeout):
				t.Fatal("explicit expiry was not detected after the traffic probe")
			}
			select {
			case err := <-done:
				if !errors.Is(err, auth.ErrSessionInvalid) {
					t.Fatal("expiry was not distinguished", err)
				}
			case <-time.After(3 * time.Second):
				_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				t.Fatal("explicit expiry did not stop the session")
			}
			if invalidations.Load() != 1 || g.authCount.Load() != 1 || saves.Load() < 2 {
				t.Fatal("expiry must invalidate once without a login loop", invalidations.Load(), g.authCount.Load(), saves.Load())
			}
			beforeDNS, beforeTCP, beforeRenewal := g.udpCount.Load(), g.tcpCount.Load(), g.renewals.Load()
			time.Sleep(40 * time.Millisecond)
			if beforeDNS != g.udpCount.Load() || beforeTCP != g.tcpCount.Load() || beforeRenewal != g.renewals.Load() {
				t.Fatal("stopped session continued maintenance")
			}
		})
	}
}
