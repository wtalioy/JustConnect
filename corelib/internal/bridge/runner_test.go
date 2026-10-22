package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestProtocolQueryProxyStopAndRestart(t *testing.T) {
	var logs bytes.Buffer
	previous := stdlog.Writer()
	stdlog.SetOutput(&logs)
	defer stdlog.SetOutput(previous)
	g := newGateway(t)
	e := New(RunProtocol)
	h := create(t, e)
	c := g.config(t)
	c.Operation = "auth_methods"
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	next(t, e, h)
	methods := next(t, e, h)
	if methods.Type != "auth_methods" || len(methods.Methods) != 1 || (methods.Methods[0].Type != "auth/smsCheckCode" || methods.Methods[0].AuthID != "fixture-primary" || methods.Methods[0].SubType != "sms") {
		t.Fatalf("methods = %+v", methods)
	}
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != OK {
		t.Fatal(ev)
	}
	c.Operation = "connect"
	c.Listeners.SOCKS, c.Listeners.HTTP = freeAddress(t), freeAddress(t)
	for round := 0; round < 2; round++ {
		startProtocol(t, e, h, c)
		ready := next(t, e, h)
		if ready.State != "ready" {
			t.Fatalf("ready = %+v", ready)
		}
		data, status := e.Resources(h, ready.Generation)
		if status != OK {
			t.Fatal(status)
		}
		var snapshot struct {
			Resources resourceSnapshot `json:"resources"`
		}
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Resources.IPs) < 2 || len(snapshot.Resources.Domains["campus.test"]) != 1 || len(snapshot.Resources.DNSRecords["campus.test"]) != 1 {
			t.Fatal("actual parsed resource data missing")
		}
		for _, row := range snapshot.Resources.IPs {
			if row.IPMin != "192.0.2.10" || row.IPMax != "192.0.2.10" || row.PortMin != 1 || row.PortMax != 65535 {
				t.Fatal("unexpected resource scope")
			}
		}
		socks, err := proxy.SOCKS5("tcp", c.Listeners.SOCKS, nil, &net.Dialer{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		connection, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", "campus.test:80")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		echo(t, connection)
		tunnel, err := net.Dial("tcp", c.Listeners.HTTP)
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Close()
		_, err = io.WriteString(tunnel, "CONNECT 192.0.2.10:80 HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		reply, err := http.ReadResponse(bufio.NewReader(tunnel), &http.Request{Method: http.MethodConnect})
		if err != nil || reply.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT = %v, %v", reply, err)
		}
		echo(t, tunnel)
		proxyURL, _ := url.Parse("http://" + c.Listeners.HTTP)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("http://campus.test/resource")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		client.CloseIdleConnections()
		if err != nil || string(body) != "vpn-response" {
			t.Fatalf("HTTP response = %q, %v", body, err)
		}
		if e.Stop(h, 3000) != OK || e.Stop(h, 3000) != OK {
			t.Fatal("protocol stop did not finish")
		}
		if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != Cancelled {
			t.Fatal(ev)
		}
		awaitClosed(t, connection)
		awaitClosed(t, tunnel)
	}
	if g.authCount.Load() != 2 || g.tcpCount.Load() != 6 {
		t.Fatalf("gateway exchanges: auth=%d, TCP=%d", g.authCount.Load(), g.tcpCount.Load())
	}
	if stdlog.Writer() != &logs || logs.Len() != 0 {
		t.Fatalf("protocol wrote to or replaced host logger: %q", logs.String())
	}
}

func TestProtocolCancellationDuringAuthenticationAndIPSetup(t *testing.T) {
	for _, phase := range []string{"authentication", "ip"} {
		t.Run(phase, func(t *testing.T) {
			g := newGateway(t)
			g.pauseIP.Store(true)
			e := New(RunProtocol)
			h := create(t, e)
			if _, status := e.Start(h, configBytes(t, g.config(t))); status != OK {
				t.Fatal(status)
			}
			next(t, e, h)
			if phase == "ip" {
				authenticate(t, e, h)
				select {
				case <-g.ipStarted:
				case <-time.After(5 * time.Second):
					t.Fatal("IP setup did not start")
				}
			} else {
				if ev := next(t, e, h); ev.Type != "authentication" {
					t.Fatal(ev)
				}
			}
			if status := e.Stop(h, 1000); status != OK {
				t.Fatalf("stop at %s = %d", phase, status)
			}
			if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != Cancelled {
				t.Fatal(ev)
			}
		})
	}
}

func TestProtocolListenerFailureRollsBackAndInvalidSessionStops(t *testing.T) {
	g := newGateway(t)
	e := New(RunProtocol)
	h := create(t, e)
	c := g.config(t)
	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	c.Listeners.SOCKS, c.Listeners.HTTP = freeAddress(t), conflict.Addr().String()
	startProtocol(t, e, h, c)
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != Internal {
		t.Fatalf("listener failure = %+v", ev)
	}
	rebound, err := net.Listen("tcp", c.Listeners.SOCKS)
	if err != nil {
		t.Fatalf("partial listener was not rolled back: %v", err)
	}
	_ = rebound.Close()
	c.Listeners.HTTP = ""
	startProtocol(t, e, h, c)
	if ev := next(t, e, h); ev.State != "ready" {
		t.Fatal(ev)
	}
	g.invalid.Store(true)
	socks, err := proxy.SOCKS5("tcp", c.Listeners.SOCKS, nil, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", "campus.test:80"); err == nil {
		_ = conn.Close()
		t.Fatal("invalid session accepted")
	}
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != SessionInvalid {
		t.Fatalf("runtime failure = %+v", ev)
	}
	if e.Stop(h, 1000) != OK || e.Destroy(h, 1000) != OK {
		t.Fatal("failed protocol did not clean up")
	}
}

func TestProtocolDNSCancellation(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	arrived := make(chan struct{})
	go func() {
		_, _, err := dns.ReadFrom(make([]byte, 2048))
		if err == nil {
			close(arrived)
		}
	}()
	e := New(RunProtocol)
	h := create(t, e)
	c := gconfigForDNS()
	c.Network.LocalDNS = dns.LocalAddr().String()
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	next(t, e, h)
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS query did not reach configured server")
	}
	if status := e.Stop(h, 1000); status != OK {
		t.Fatalf("stop during DNS = %d", status)
	}
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != Cancelled {
		t.Fatal(ev)
	}
}
func gconfigForDNS() Config {
	var c Config
	c.SchemaVersion = ABIVersion
	c.Server.Host = "gateway.test"
	c.Server.Port = 443
	return c
}

func TestNativeProtocolHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_PROTOCOL_HOST")
	if host == "" {
		t.Skip("native host is exercised by the Core ABI CTest target")
	}
	g := newGateway(t)
	g.resumeCookies.Store(true)
	g.loopbackResource.Store(true)
	var foreignRequests atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>unexpected foreign browser request</body></html>`)
	}))
	defer other.Close()
	g.browserURL.Store(other.URL)
	g.nextService.Store("auth/bindAuthDevice")
	c := g.config(t)
	c.Listeners.SOCKS, c.Listeners.HTTP = freeAddress(t), freeAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, host, "--gateway", string(configBytes(t, c)))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native protocol host: %v\n%s", err, output)
	}
	expectedTCP := int32(2)
	if strings.Contains(string(output), "PASS: initial native protection and live exact campus/original choices") {
		expectedTCP++
	}
	if !strings.Contains(string(output), "PASS: native protocol session") || g.authCount.Load() != 1 || g.deviceBinds.Load() != 1 || g.tcpCount.Load() != expectedTCP {
		t.Fatalf("missing actual protocol exchanges: auth=%d TCP=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), output)
	}
	if strings.Contains(string(output), "PASS: browser TLS policy") && g.browserRedirects.Load() != 1 {
		t.Fatal("browser did not exercise the same-origin resource redirect")
	}
	if strings.Contains(string(output), "PASS: native cache restoration") && g.cacheProbes.Load() != 1 {
		t.Fatal("native host did not verify restored cookies with the server")
	}
	if foreignRequests.Load() != 0 {
		t.Fatal("browser TLS bypass escaped the configured gateway origin")
	}
	t.Log(string(output))
}

func TestStaleAuthenticationIdentityReportsRequeryWithoutLogin(t *testing.T) {
	g := newGateway(t)
	e := New(RunProtocol)
	h := create(t, e)
	config := g.config(t)
	config.Auth.AuthID = "no-longer-present"
	config.Auth.SubType = "sms"
	if _, status := e.Start(h, configBytes(t, config)); status != OK {
		t.Fatal(status)
	}
	if ev := next(t, e, h); ev.State != "starting" {
		t.Fatal(ev)
	}
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != AuthMethodChanged {
		t.Fatalf("stale identity: %+v", ev)
	}
	if g.authCount.Load() != 0 {
		t.Fatal("stale selection must not attempt login")
	}
}

func TestProtocolReportsTrustProtocolAndNetworkFailures(t *testing.T) {
	g := newGateway(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer plain.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	closed.Close()
	for _, test := range []struct {
		name, address string
		status        Status
	}{
		{"untrusted certificate", g.HTTP.Listener.Addr().String(), TLSTrust},
		{"plaintext instead of TLS", plain.Listener.Addr().String(), TLSProtocol},
		{"connection refused", closedAddress, NetworkFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := g.config(t)
			c.Operation = "auth_methods"
			c.TLS.CAPEM = ""
			address, port, _ := net.SplitHostPort(test.address)
			number, _ := strconv.Atoi(port)
			c.Server.Host = address
			c.Server.Port = uint16(number)
			e := New(RunProtocol)
			h := create(t, e)
			if _, status := e.Start(h, configBytes(t, c)); status != OK {
				t.Fatal(status)
			}
			next(t, e, h)
			if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != test.status {
				t.Fatalf("event=%+v", ev)
			}
			if g.authCount.Load() != 0 {
				t.Fatal("failure sent authentication")
			}
		})
	}
}

func TestProtocolTrustedDeviceDeclineAndUnknownStep(t *testing.T) {
	for _, service := range []string{"auth/bindAuthDevice", "auth/futureStep?private-marker"} {
		t.Run(service, func(t *testing.T) {
			g := newGateway(t)
			g.nextService.Store(service)
			e := New(RunProtocol)
			h := create(t, e)
			if _, status := e.Start(h, configBytes(t, g.config(t))); status != OK {
				t.Fatal(status)
			}
			next(t, e, h)
			authenticate(t, e, h)
			want := AuthUnsupported
			if service == "auth/bindAuthDevice" {
				ev := next(t, e, h)
				if ev.Type != "authentication" || ev.Challenge.Kind != "trusted_device" {
					t.Fatal(ev)
				}
				response := []byte(fmt.Sprintf(`{"schema_version":1,"generation":"%d","request_id":"%d","action":"cancel"}`, ev.Generation, ev.RequestID))
				if status := e.Respond(h, response); status != OK {
					t.Fatal(status)
				}
				want = Cancelled
			}
			terminal := next(t, e, h)
			if terminal.Type != "terminal" || terminal.Status != want || strings.Contains(terminal.Message, "private-marker") {
				t.Fatal(terminal)
			}
			if g.deviceBinds.Load() != 0 {
				t.Fatal("unconfirmed device was bound")
			}
		})
	}
}

func TestProtocolOversizedAuthenticationBodyReportsLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/manifest" {
			t.Error("sent authentication after oversized manifest")
		}
		io.WriteString(w, strings.Repeat("x", (8<<20)+1))
	}))
	defer server.Close()
	c, status := ParseConfig([]byte(configJSON))
	if status != OK {
		t.Fatal(status)
	}
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	c.Server.Host, c.Server.Port = host, uint16(number)
	c.TLS.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	e := New(RunProtocol)
	h := create(t, e)
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	next(t, e, h)
	if terminal := next(t, e, h); terminal.Type != "terminal" || terminal.Status != Limit {
		t.Fatal(terminal)
	}
}
