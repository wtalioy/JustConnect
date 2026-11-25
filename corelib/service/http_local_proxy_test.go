package service

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestStartLocalClosesBothReservedSocketsOnCancellation(t *testing.T) {
	socks, err := ListenLoopback(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	httpListener, err := ListenLoopback(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpListener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if listeners, err := StartLocal(ctx, socks, httpListener, nil, nil); listeners != nil || err != context.Canceled {
		t.Fatalf("StartLocal after cancellation: %v, %v", listeners, err)
	}
	for _, listener := range []net.Listener{socks, httpListener} {
		rebound, err := ListenLoopback(t.Context(), listener.Addr().String())
		if err != nil {
			t.Fatalf("reserved listener survived cancellation: %v", err)
		}
		rebound.Close()
	}
}

// localProxyFixture mirrors the session's local-proxy construction: a strict
// user dialer (alwaysUseVPN, like dial.NewDialer(..., options.LocalProxy)) on
// top of a tunnel stack that reaches campus origins, fronted by StartLocal's
// SOCKS and HTTP listeners.
type localProxyFixture struct {
	t         *testing.T
	listeners *Listeners
	origin    *httptest.Server
	campus    string // "host" the resolver maps into the tunnel
	dialer    *dial.Dialer
	context   context.Context
	cancel    context.CancelFunc

	mu       sync.Mutex
	codes    []string
	failures []error
}

func newLocalProxyFixture(t *testing.T, grants client.DomainResources, ipResources []client.IPResource) *localProxyFixture {
	t.Helper()
	// The campus origin stands in for the tunnel: whatever the stack dials
	// lands on this HTTP server, exactly like a real campus web service.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "campus-origin")
	}))
	t.Cleanup(origin.Close)
	originAddr := strings.TrimPrefix(origin.URL, "http://")

	fakeStack := dialStackFunc(func(ctx context.Context, address *net.TCPAddr) (net.Conn, error) {
		return net.Dial("tcp", originAddr)
	})
	resolver := resolve.NewResolver(fakeStack, "", "", 60, grants,
		map[string][]net.IP{"campus.example.edu": {net.ParseIP("203.0.113.7")}}, false)
	t.Cleanup(func() { resolver.Close() })
	// The tunnel's TCP node answers, so granted campus dials reach the origin.
	dialer := dial.NewDialer(fakeStack, resolver, ipResources, true)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &localProxyFixture{t: t, origin: origin, campus: "campus.example.edu", dialer: dialer, context: ctx, cancel: cancel}
	ready := make(chan struct{})
	listeners, err := StartLocal(ctx, socksListener, httpListener, dialer, func(code string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if code == "listeners_failed" || code == "proxy_worker_panicked" {
			f.failures = append(f.failures, errListenerDiagnostic(code))
		}
		f.codes = append(f.codes, code)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.listeners = listeners
	t.Cleanup(func() {
		cancel()
		listeners.Close()
		<-ready
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, failure := range f.failures {
			t.Errorf("listener failure: %v", failure)
		}
	})
	go func() {
		defer close(ready)
		select {
		case err := <-listeners.Errors():
			f.mu.Lock()
			defer f.mu.Unlock()
			f.failures = append(f.failures, err)
		case <-ctx.Done():
		}
	}()
	return f
}

func (f *localProxyFixture) diagnosticCodes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.codes)
}

type listenerDiagnosticError string

func (e listenerDiagnosticError) Error() string { return "listener diagnostic: " + string(e) }
func errListenerDiagnostic(code string) error   { return listenerDiagnosticError(code) }

// dialStackFunc adapts a function into a stack.Stack.
type dialStackFunc func(context.Context, *net.TCPAddr) (net.Conn, error)

func (f dialStackFunc) DialTCP(ctx context.Context, address *net.TCPAddr) (net.Conn, error) {
	return f(ctx, address)
}
func (f dialStackFunc) DialUDP(ctx context.Context, address *net.UDPAddr) (net.Conn, error) {
	return nil, dial.ErrACLDenied
}

// requestViaHTTPProxy sends one absolute-form request through the HTTP entry.
func (f *localProxyFixture) requestViaHTTPProxy(target string) *http.Response {
	f.t.Helper()
	entry := f.listeners.Addresses().HTTP
	proxyURL := "http://" + entry
	client := &http.Client{
		Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(proxyURL) }},
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(target)
	if err != nil {
		f.t.Fatalf("HTTP proxy request to %s failed: %v", target, err)
	}
	f.t.Cleanup(func() { response.Body.Close() })
	return response
}

// connectViaHTTPProxy performs one raw CONNECT through the HTTP entry and
// returns the established tunnel and the status line.
func (f *localProxyFixture) connectViaHTTPProxy(hostPort string) (net.Conn, string) {
	f.t.Helper()
	entry, line := f.connectStatus(hostPort)
	if !strings.Contains(line, "200") {
		f.t.Fatalf("CONNECT to %s was refused: %s", hostPort, strings.TrimSpace(line))
	}
	return entry, line
}

// connectStatus performs one raw CONNECT and returns the status line plus the
// open connection, for tests that exercise refusals as well as tunnels.
func (f *localProxyFixture) connectStatus(hostPort string) (net.Conn, string) {
	f.t.Helper()
	entry, err := net.Dial("tcp", f.listeners.Addresses().HTTP)
	if err != nil {
		f.t.Fatal(err)
	}
	request := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n\r\n"
	if _, err := entry.Write([]byte(request)); err != nil {
		f.t.Fatal(err)
	}
	reader := bufio.NewReader(entry)
	line, err := reader.ReadString('\n')
	if err != nil {
		f.t.Fatalf("CONNECT reply lost: %v", err)
	}
	f.t.Cleanup(func() { entry.Close() })
	return entry, line
}

func TestLocalProxyHTTPEntryServesCampusResources(t *testing.T) {
	f := newLocalProxyFixture(t, client.DomainResources{
		"campus.example.edu": {{Protocol: "tcp", PortMin: 80, PortMax: 80}},
	}, nil)

	// Plain HTTP through the HTTP entry reaches the campus origin.
	response := f.requestViaHTTPProxy("http://campus.example.edu/")
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "campus-origin" {
		t.Fatalf("campus GET through the HTTP entry failed: %d %q", response.StatusCode, body)
	}

	// CONNECT (HTTPS browsing) tunnels to the campus origin too.
	tunnel, line := f.connectViaHTTPProxy("campus.example.edu:80")
	if !strings.Contains(line, "200") {
		t.Fatalf("campus CONNECT through the HTTP entry failed: %s", strings.TrimSpace(line))
	}
	if _, err := tunnel.Write([]byte("GET / HTTP/1.1\r\nHost: campus.example.edu\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(tunnel)
	if err != nil || !strings.Contains(string(reply), "campus-origin") {
		t.Fatalf("campus CONNECT tunnel lost the origin reply: %q %v", reply, err)
	}
}

func TestLocalProxyHTTPEntryMatchesSOCKSEntry(t *testing.T) {
	f := newLocalProxyFixture(t, client.DomainResources{
		"campus.example.edu": {{Protocol: "tcp", PortMin: 80, PortMax: 80}},
	}, nil)
	// Both entries serve the same dialer; a campus destination reachable via
	// SOCKS must be equally reachable via HTTP.
	response := f.requestViaHTTPProxy("http://campus.example.edu/")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP entry status %d", response.StatusCode)
	}
	conn, err := net.Dial("tcp", f.listeners.Addresses().SOCKS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("SOCKS entry greeting failed: %v %x", err, reply)
	}
}

// A browser pointed straight at the HTTP entry is a local-proxy user flow:
// campus names, campus IP literals, and refused non-campus destinations must
// behave exactly like the SOCKS entry, and refusals must name their stage.
func TestLocalProxyHTTPEntryKeepsCampusIPNonCampusAndDiagnosticsApart(t *testing.T) {
	f := newLocalProxyFixture(t, client.DomainResources{
		"campus.example.edu": {{Protocol: "tcp", PortMin: 80, PortMax: 80}},
	}, []client.IPResource{{IPMin: net.IPv4(203, 0, 113, 7), IPMax: net.IPv4(203, 0, 113, 7),
		PortMin: 80, PortMax: 80, Protocol: "tcp"}})

	// A campus destination entered by IP still reaches the tunnel without DNS.
	tunnel, _ := f.connectViaHTTPProxy("203.0.113.7:80")
	if _, err := tunnel.Write([]byte("GET / HTTP/1.1\r\nHost: campus.example.edu\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(tunnel)
	if err != nil || !strings.Contains(string(reply), "campus-origin") {
		t.Fatalf("campus IP literal lost the tunnel reply: %q %v", reply, err)
	}

	// A non-campus hostname has no campus DNS source in strict mode; the entry
	// refuses it and names the DNS stage instead of failing silently.
	_, line := f.connectStatus("public.example.com:80")
	if !strings.Contains(line, "500") {
		t.Fatalf("non-campus hostname was not refused: %s", strings.TrimSpace(line))
	}

	// An ungranted IP literal is refused by the resource policy.
	_, line = f.connectStatus("198.51.100.9:80")
	if !strings.Contains(line, "500") {
		t.Fatalf("ungranted IP literal was not refused: %s", strings.TrimSpace(line))
	}

	codes := f.diagnosticCodes()
	if !slices.Contains(codes, "http_dns_failed") {
		t.Fatalf("non-campus DNS refusal emitted no diagnostic: %v", codes)
	}
	if !slices.Contains(codes, "http_destination_denied") {
		t.Fatalf("ungranted destination refusal emitted no diagnostic: %v", codes)
	}
	if slices.Contains(codes, "http_dial_failed") {
		t.Fatalf("an unclassified dial failure leaked through: %v", codes)
	}
}
