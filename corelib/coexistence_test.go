package corelib

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

type observeProxy func(context.Context) (mihomo.ProxyInfo, error)

func (f observeProxy) ObserveProxy(ctx context.Context, _ []mihomo.ListenerProof) (mihomo.ProxyInfo, error) {
	return f(ctx)
}

func TestSessionOrdinaryExitFollowsObservedProxyAndTUN(t *testing.T) {
	if os.Getenv("JC_TEST_MIHOMO_BINARY") == "" {
		t.Skip("requires the pinned owned Mihomo runtime")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "owned ordinary exit") }))
	defer server.Close()
	fixture := testmihomo.StartConfiguredBinary(t, "127.0.0.1:9", true, map[string]any{"mixed-port": testmihomo.ProxyPort(t)})
	processes, err := mihomo.Processes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var controller *mihomo.Client
	for _, process := range processes {
		if process.PID == fixture.PID {
			controller, err = mihomo.Inspect(t.Context(), process)
			break
		}
	}
	if err != nil || controller == nil {
		t.Fatal("owned controller was not identified", err)
	}
	defer controller.Close()
	info, err := controller.ObserveProxy(t.Context())
	if err != nil || info.Proxy == nil || len(info.Endpoints) == 0 {
		t.Fatal("owned data listener was not verified", err)
	}
	// Only switch facts are injected; traffic always uses the real native-owned proxy.
	tun := false
	var observationError error
	u := &sessionUpstream{gate: make(chan struct{}, 1), source: observeProxy(func(context.Context) (mihomo.ProxyInfo, error) {
		current := info
		current.TunEnabled = tun
		return current, observationError
	})}
	s := NewSession(Options{})
	s.upstream.Store(u)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if dial := u.dialer(); dial != nil {
			return dial(ctx, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, test := range []struct {
		name                  string
		endpoints             []string
		tun, managed, blocked bool
	}{
		{"both off", nil, false, false, false},
		{"system proxy on", info.Endpoints, false, false, true},
		{"unrelated proxy", []string{"127.0.0.1:1"}, false, false, false},
		{"managed frontend retains upstream across port changes", []string{"127.0.0.1:1"}, false, true, true},
		{"TUN on", nil, true, false, true},
		{"both on", info.Endpoints, true, false, true},
		{"both off again", nil, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tun = test.tun
			if err := s.RefreshCoexistence(t.Context(), test.endpoints, test.managed); err != nil {
				t.Fatal(err)
			}
			state := s.Coexistence()
			if !state.Available || state.Active != test.blocked || state.TUN != tun {
				t.Fatal("wrong actual exit selection", state)
			}
			response, err := client.Get(server.URL)
			if test.blocked {
				if err == nil {
					response.Body.Close()
					t.Fatal("selected rejecting Clash exit fell back to direct")
				}
				return
			}
			if err != nil {
				t.Fatal("disabled or unrelated proxy prevented direct traffic", err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "owned ordinary exit" {
				t.Fatal("direct exit payload lost", err)
			}
		})
	}
	observationError = mihomo.ErrUnavailable
	if err := s.RefreshCoexistence(t.Context(), info.Endpoints, true); !errors.Is(err, observationError) || s.Coexistence().Available {
		t.Fatal("unavailable controller was mistaken for a confirmed ordinary exit", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.RefreshCoexistence(ctx, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled refresh was not cancelled", err)
	}
	s.upstream.Store(nil)
	if err := s.RefreshCoexistence(t.Context(), nil, false); err == nil {
		t.Fatal("stopped generation accepted an upstream change")
	}
}

func TestUnverifiedPrivilegedListenerCannotFallBackToDirect(t *testing.T) {
	var directRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directRequests.Add(1)
		io.WriteString(w, "unexpected direct exit")
	}))
	defer server.Close()
	for _, test := range []struct {
		name                        string
		info                        mihomo.ProxyInfo
		observationError, wantError error
	}{
		{"pending ownership", mihomo.ProxyInfo{ListenerRequest: &mihomo.ListenerRequest{PID: 1, Started: 1, Endpoints: []string{"127.0.0.1:7897"}}}, nil, nil},
		{"controller unavailable", mihomo.ProxyInfo{}, mihomo.ErrUnavailable, mihomo.ErrUnavailable},
		{"controller timeout", mihomo.ProxyInfo{}, context.DeadlineExceeded, context.DeadlineExceeded},
		{"TUN lacks proxy", mihomo.ProxyInfo{RuntimeState: mihomo.RuntimeState{TunEnabled: true}}, nil, mihomo.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &sessionUpstream{gate: make(chan struct{}, 1), source: observeProxy(func(context.Context) (mihomo.ProxyInfo, error) { return test.info, test.observationError })}
			session := NewSession(Options{})
			session.upstream.Store(upstream)
			err := session.RefreshCoexistence(t.Context(), []string{"127.0.0.1:7897"}, true)
			if !errors.Is(err, test.wantError) {
				t.Errorf("wrong unconfirmed observation result: %v", err)
			}
			transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if selected := upstream.dialer(); selected != nil {
					return selected(ctx, network, address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}}
			defer transport.CloseIdleConnections()
			if response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(server.URL); err == nil {
				response.Body.Close()
				t.Fatal("unconfirmed upstream escaped to direct traffic")
			}
		})
	}
	if directRequests.Load() != 0 {
		t.Fatal("unverified ownership sent traffic to the native exit", directRequests.Load())
	}
}

func TestFailedProxyObservationKeepsSelectedExitUntilConfirmedOff(t *testing.T) {
	var directRequests, selectedRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directRequests.Add(1)
		io.WriteString(w, "confirmed direct exit")
	}))
	defer server.Close()
	previousFailure := errors.New("selected proxy rejected request")
	var observationError error
	upstream := &sessionUpstream{gate: make(chan struct{}, 1), source: observeProxy(func(context.Context) (mihomo.ProxyInfo, error) { return mihomo.ProxyInfo{}, observationError })}
	upstream.route.Store(&upstreamRoute{dial: func(context.Context, string, string) (net.Conn, error) {
		selectedRequests.Add(1)
		return nil, previousFailure
	}})
	session := NewSession(Options{})
	session.upstream.Store(upstream)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if selected := upstream.dialer(); selected != nil {
			return selected(ctx, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, failure := range []error{mihomo.ErrUnavailable, context.DeadlineExceeded} {
		observationError = failure
		if err := session.RefreshCoexistence(t.Context(), nil, true); !errors.Is(err, failure) {
			t.Errorf("lost actual observation failure: %v", err)
		}
		response, err := client.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		if !errors.Is(err, previousFailure) {
			t.Fatal("request left its previously selected exit", err)
		}
	}
	if directRequests.Load() != 0 || selectedRequests.Load() != 2 {
		t.Fatal("unconfirmed observation bypassed the selected exit")
	}
	observationError = nil
	if err := session.RefreshCoexistence(t.Context(), nil, false); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("confirmed absence did not release ordinary routing", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "confirmed direct exit" || directRequests.Load() != 1 {
		t.Fatal("confirmed direct response lost", err)
	}
}
