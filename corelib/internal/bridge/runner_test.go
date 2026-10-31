package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestProtocolQueryProxyStopAndRestart(t *testing.T) {
	const childMarker = "JC_PROTOCOL_LOGGER_CHILD"
	if os.Getenv(childMarker) != "1" {
		// Isolate the process logger while retaining the complete parallel data-plane regression.
		t.Parallel()
		ctx := t.Context()
		if deadline, bounded := t.Deadline(); bounded {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		command := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run=^"+t.Name()+"$")
		command.Env = append(os.Environ(), childMarker+"=1")
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" ")) {
			t.Fatalf("isolated protocol/logging regression did not pass: %v\n%s", err, output)
		}
		return
	}
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
	c.Listeners.SOCKS, c.Listeners.HTTP = "127.0.0.1:0", "[::1]:0"
	for round := 0; round < 2; round++ {
		startProtocol(t, e, h, c)
		ready := next(t, e, h)
		if ready.State != "ready" {
			t.Fatalf("ready = %+v", ready)
		}
		device := exerciseProtocolTUN(t, e, h, ready.Generation, false)
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
		listeners := snapshot.Resources.Listeners
		for _, address := range []string{listeners.SOCKS, listeners.HTTP} {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
				t.Fatal("resource snapshot did not report a bound loopback endpoint", address, err)
			}
		}
		for _, row := range snapshot.Resources.IPs {
			if row.IPMin != "192.0.2.10" || row.IPMax != "192.0.2.10" || row.PortMin != 1 || row.PortMax != 65535 {
				t.Fatal("unexpected resource scope")
			}
		}
		socks, err := proxy.SOCKS5("tcp", listeners.SOCKS, nil, &net.Dialer{})
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
		tunnel, err := net.Dial("tcp", listeners.HTTP)
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
		proxyURL, _ := url.Parse("http://" + listeners.HTTP)
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
		for _, address := range []string{listeners.SOCKS, listeners.HTTP} {
			rebound, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("reported listener was retained after session shutdown", address, err)
			}
			rebound.Close()
		}
		if _, err := device.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("session retained TUN device: %v", err)
		}
		if status := e.AttachTUN(h, ready.Generation, device, 1400, false); status != StaleRequest {
			t.Fatal(status)
		}
	}
	if g.authCount.Load() != 2 || g.tcpCount.Load() != 6 || g.udpCount.Load() != 2 {
		t.Fatalf("gateway exchanges: auth=%d, TCP=%d, UDP=%d", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load())
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
	if strings.Contains(string(output), "PASS: initial native address/name protection and live exact campus/original choices") {
		expectedTCP += 2
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

func runNativeTUNHost(t *testing.T, killed bool) (*gateway, []byte) {
	t.Helper()
	host := os.Getenv("JC_NATIVE_TUN_HOST")
	inherited := os.Getenv("JC_NATIVE_TUN_FD")
	macAuthorization := os.Getenv("JC_NATIVE_TUN_MAC_AUTH_FD")
	if host == "" || (inherited == "" && macAuthorization == "" && os.Getenv("JC_NATIVE_TUN_HELPER_OWNER") == "") {
		t.Skip("native TUN/C ABI handoff runs in a guarded namespace or disposable macOS runner")
	}
	mode := os.Getenv("JC_NATIVE_NETWORK_AUTHORIZATION")
	if mode != "" && (runtime.GOOS != "darwin" || macAuthorization == "" || (mode != "cancel" && mode != "exit")) {
		t.Fatal("authorization scenarios require the disposable macOS authorization fixture")
	}
	if killed && (runtime.GOOS != "darwin" || macAuthorization == "" || os.Getenv("JC_NATIVE_NETWORK_HELPER_LOSS") != "1") {
		t.Fatal("process crash requires the disposable macOS helper fixture")
	}
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("requires an ordinary caller")
	}
	if runtime.GOOS == "linux" {
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") && strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")) != "0000000000000000" {
				t.Fatal("native data plane retained capabilities")
			}
		}
	}
	g := newGateway(t)
	g.resourceIP.Store("198.18.0.6")
	verifyOriginalDNS := startNativeOriginalDNSSource(t)
	original := startNativeOriginalPeer(t, g)
	if macAuthorization != "" || os.Getenv("JC_NATIVE_NETWORK_SESSION") == "1" {
		enableNativeSSH(t, g)
	}
	if os.Getenv("JC_NATIVE_TUN_DNS") == "1" {
		g.nativeDNS.Store(true)
		g.probeDNS.Store(true)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, host, "--tun-gateway", string(configBytes(t, g.config(t))))
	if inherited != "" {
		descriptor, err := strconv.Atoi(inherited)
		if err != nil || descriptor < 3 {
			t.Fatal("requires a borrowed TUN fd")
		}
		file := os.NewFile(uintptr(descriptor), "inherited-tun")
		defer file.Close()
		command.Args = append(command.Args, "3")
		command.ExtraFiles = []*os.File{file}
	}
	if macAuthorization != "" {
		if runtime.GOOS != "darwin" || inherited != "" {
			t.Fatal("network authorization is separate from native device ownership")
		}
		descriptor, err := strconv.Atoi(macAuthorization)
		if err != nil || descriptor < 3 {
			t.Fatal("requires the inherited network authorization pipe")
		}
		file := os.NewFile(uintptr(descriptor), "macos-network-authorization")
		defer file.Close()
		command.Args = append(command.Args, "3")
		command.ExtraFiles = []*os.File{file}
	}
	output, err := command.CombinedOutput()
	if killed {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != -1 || ctx.Err() != nil {
			t.Fatalf("native host did not terminate by the injected signal: %v\n%s", err, output)
		}
	} else if err != nil {
		t.Fatalf("native TUN/C ABI host: %v; auth=%d TCP=%d UDP=%d DNS=%d\n%s", err, g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	if original != nil && (original.tcp.Load() != 2 || original.udp.Load() != 4) {
		t.Fatalf("missing actual original-side exchanges: TCP=%d UDP=%d\n%s", original.tcp.Load(), original.udp.Load(), output)
	}
	if original != nil && (original.nonCampusTCP.Load() != 1 || original.nonCampusUDP.Load() != 2) {
		t.Fatalf("missing non-campus original exchanges: TCP=%d UDP=%d\n%s", original.nonCampusTCP.Load(), original.nonCampusUDP.Load(), output)
	}
	verifyOriginalDNS()
	return g, output
}

func TestNativeTUNHost(t *testing.T) {
	g, output := runNativeTUNHost(t, false)
	expectedAuth := int32(2)
	if os.Getenv("JC_NATIVE_NETWORK_AUTHORIZATION") == "cancel" {
		expectedAuth++ // The cancelled prefix reached real authentication before network authorization.
	}
	extraUDP := int32(0)
	extraTCP := int32(0)
	if os.Getenv("JC_NATIVE_NETWORK_OBSERVE") == "1" {
		extraUDP = 2
	}
	if os.Getenv("JC_NATIVE_NETWORK_POLICY") == "1" {
		extraTCP, extraUDP = 2, extraUDP+4
	}
	expectedSSH := int32(0)
	if g.sshHandler.Load() != nil {
		expectedSSH = 4
	}
	if !bytes.Contains(output, []byte("PASS: ordinary native TCP/UDP")) || g.authCount.Load() != expectedAuth || g.tcpCount.Load() != 2+extraTCP+expectedSSH || g.sshCount.Load() != expectedSSH || g.udpCount.Load() != 4+extraUDP+g.nativeDNSQueries.Load() || (g.nativeDNS.Load() && g.nativeDNSQueries.Load() < 2) {
		t.Fatalf("missing actual TUN/campus exchanges: auth=%d TCP=%d UDP=%d SSH=%d/%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.sshCount.Load(), expectedSSH, output)
	}
	if g.nativeDNS.Load() {
		t.Logf("domain-only TCP/80 via actual campus CNAME DNS: queries=%d, TCP=%d, UDP=%d", g.nativeDNSQueries.Load(), g.tcpCount.Load(), g.udpCount.Load())
	}
	t.Log(string(output))
}

func TestNativeTUNAuthorizationExit(t *testing.T) {
	if os.Getenv("JC_NATIVE_NETWORK_AUTHORIZATION") != "exit" {
		t.Skip("ordered exit with pending system authorization runs in the disposable macOS fixture")
	}
	g, output := runNativeTUNHost(t, false)
	if !bytes.Contains(output, []byte("PASS: macOS ordered application exit while system authorization is still pending")) || g.authCount.Load() != 1 || g.tcpCount.Load() != 0 || g.udpCount.Load() != 0 || g.nativeDNSQueries.Load() != 0 {
		t.Fatalf("authorization exit did not stop before network activation: auth=%d TCP=%d UDP=%d DNS=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	t.Log(string(output))
}

func TestNativeTUNProcessCrash(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("JC_NATIVE_NETWORK_HELPER_LOSS") != "1" {
		t.Skip("full process crash runs in the disposable macOS helper fixture")
	}
	g, output := runNativeTUNHost(t, true)
	if g.authCount.Load() != 1 || g.tcpCount.Load() != 3 || g.sshCount.Load() != 2 || g.nativeDNSQueries.Load() < 1 || g.udpCount.Load() != 2+g.nativeDNSQueries.Load() {
		t.Fatalf("process was killed before actual native traffic: auth=%d TCP=%d UDP=%d DNS=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	t.Log("PASS: signed macOS Qt/core killed after actual system DNS, TCP and UDP exchanges")
	t.Log(string(output))
}
