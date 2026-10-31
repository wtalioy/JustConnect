package underlay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestMain(m *testing.M) {
	if testmihomo.Run() {
		os.Exit(0)
	}
	// Binding unit tests must not discover an unrelated desktop or another package's fixture.
	discoverController = func(context.Context) (*mihomo.Client, error) { return nil, nil }
	os.Exit(m.Run())
}

func ownedController(t *testing.T, options testmihomo.Options) (*mihomo.Client, *testmihomo.Fixture) {
	t.Helper()
	fixture := testmihomo.Start(t, options)
	processes, err := mihomo.Processes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range processes {
		if process.PID == fixture.PID {
			client, err := mihomo.Inspect(t.Context(), process)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			return client, fixture
		}
	}
	t.Fatal("owned process was not visible to native discovery")
	return nil, nil
}

func useController(t *testing.T, client *mihomo.Client) {
	t.Helper()
	original := discoverController
	t.Cleanup(func() { discoverController = original })
	discoverController = func(context.Context) (*mihomo.Client, error) { return client, nil }
}

func refuseSystemDial(t *testing.T) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	original := dialOnInterface
	t.Cleanup(func() { dialOnInterface = original })
	// Observe the fallback boundary without changing net.DefaultResolver during canceled HTTP dials.
	dialOnInterface = func(context.Context, string, string, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("system fallback must not supply the control connection")
	}
	return &calls
}

func TestControllerRealResolutionPreservesTLSIdentityAndLoopback(t *testing.T) {
	for _, kind := range []string{"tcp", "ipc"} {
		t.Run(kind, func(t *testing.T) {
			controller, fixture := ownedController(t, testmihomo.Options{Transport: kind})
			useController(t, controller)
			var requests atomic.Int32
			systemDials := refuseSystemDial(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" {
					t.Error("logical TLS host was rewritten to an IP")
				}
				requests.Add(1)
				io.WriteString(w, "verified gateway")
			}))
			defer server.Close()
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			for _, stage := range []string{"auth-methods", "login", "gateway", "reconnect"} {
				dialer, err := New(Options{AutoDetect: true})
				if err != nil {
					t.Fatal(err)
				}
				client := server.Client()
				transport := client.Transport.(*http.Transport).Clone()
				transport.Proxy = nil
				transport.DialContext = dialer.DialContext
				client.Transport = transport
				response, err := client.Get("https://example.com:" + port + "/" + stage)
				if err != nil {
					dialer.Close()
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(data) != "verified gateway" {
					t.Fatal("real-address TLS exchange failed")
				}
				if stage == "login" {
					response, err = client.Get("https://wrong-name.example.test:" + port)
					if err == nil {
						response.Body.Close()
						t.Fatal("real-address resolution disabled TLS host validation")
					}
				}
				transport.CloseIdleConnections()
				dialer.Close()
			}
			queries, _ := fixture.Counts(t)
			if requests.Load() != 4 || queries == 0 || systemDials.Load() != 0 {
				t.Fatalf("control exchanges=%d API DNS=%d system fallbacks=%d", requests.Load(), queries, systemDials.Load())
			}
		})
	}
}

func TestCloseCancelsControllerDNSAndJoinsActiveDial(t *testing.T) {
	controller, fixture := ownedController(t, testmihomo.Options{Transport: "ipc"})
	useController(t, controller)
	dialer, err := New(Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, err := dialer.DialContext(t.Context(), "tcp", "stall.example.test:443")
		if connection != nil {
			connection.Close()
		}
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		count, _ := fixture.Counts(t)
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			dialer.Close()
			t.Fatal("DNS request did not reach owned controller")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { dialer.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("underlay close did not join controller requests")
	}
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled lookup retained its dial")
	}
	deadline = time.Now().Add(time.Second)
	for {
		_, count := fixture.Counts(t)
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller retained the cancelled DNS handler")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestControllerTunnelIsNotUsedAsUnderlay(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			name = iface.Name
			break
		}
	}
	if name == "" {
		t.Skip("no available non-loopback interface for exclusion")
	}
	controller, fixture := ownedController(t, testmihomo.Options{Transport: "tcp", TunEnabled: true, TunDevice: name})
	useController(t, controller)
	original := findDefaultInterface
	findDefaultInterface = func() string { return name }
	t.Cleanup(func() { findDefaultInterface = original })
	for _, autoDetect := range []bool{true, false} {
		dialer, err := New(Options{AutoDetect: autoDetect})
		if err != nil {
			t.Fatal(err)
		}
		connection, err := dialer.DialContext(t.Context(), "tcp", "gateway.example.test:443")
		if connection != nil {
			connection.Close()
		}
		dialer.Close()
		if err == nil || !strings.Contains(err.Error(), "underlay interface") {
			t.Fatal("controller's TUN became a control exit", autoDetect, err)
		}
	}
	queries, _ := fixture.Counts(t)
	if queries != 0 {
		t.Fatal("unsafe exit reached DNS or a destination connection")
	}
}

func TestControllerTunnelSelectsOriginalExitWithDefaultOptions(t *testing.T) {
	name := findDefaultInterface()
	if !usableInterface(name, nil) {
		t.Skip("no original default interface is available")
	}
	controller, _ := ownedController(t, testmihomo.Options{Transport: "ipc", TunEnabled: true, TunDevice: "fixture-tun"})
	useController(t, controller)
	original := findDefaultInterface
	findDefaultInterface = func() string { return name }
	t.Cleanup(func() { findDefaultInterface = original })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "original exit") }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	dialer, err := New(Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get("http://gateway.example.test:" + port)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "original exit" || dialer.InterfaceName() != name {
		t.Fatalf("default control did not select the original exit: interface=%q err=%v", dialer.InterfaceName(), err)
	}
}

func TestControllerInitializationWaitIsCancelable(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(fmt.Sprint("observe=", observe), func(t *testing.T) {
			original := discoverController
			t.Cleanup(func() { discoverController = original })
			entered := make(chan struct{})
			var calls atomic.Int32
			discoverController = func(ctx context.Context) (*mihomo.Client, error) {
				if calls.Add(1) == 1 {
					close(entered)
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			dialer, err := New(Options{AutoDetect: false})
			if err != nil {
				t.Fatal(err)
			}
			first := make(chan error, 1)
			go func() { _, err := dialer.DialContext(t.Context(), "tcp", "gateway.example.test:443"); first <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("controller initialization did not start")
			}
			ctx, cancel := context.WithCancel(t.Context())
			second := make(chan error, 1)
			go func() {
				var err error
				if observe {
					_, err = dialer.ObserveProxy(ctx)
				} else {
					_, err = dialer.DialContext(ctx, "tcp", "other.example.test:443")
				}
				second <- err
			}()
			cancel()
			select {
			case err = <-second:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled waiter retained the controller gate")
			}
			if calls.Load() != 1 {
				t.Fatal("concurrent initialization was duplicated")
			}
			dialer.Close()
			select {
			case err = <-first:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("close did not cancel initialization")
			}

		})
	}
}
