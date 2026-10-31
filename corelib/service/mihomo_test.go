package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestOfficialMihomoCampusIngressEnforcesSharedResources(t *testing.T) {
	if os.Getenv("JC_TEST_MIHOMO_BINARY") == "" {
		t.Skip("set JC_TEST_MIHOMO_BINARY for the official campus ingress integration")
	}
	var webRequests, originalCalls atomic.Int32
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webRequests.Add(1)
		io.WriteString(w, "owned campus HTTP")
	}))
	defer web.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], peer)
		}
	}()
	defer func() { udp.Close(); <-done }()
	ip := net.ParseIP("203.0.113.7")
	campus := &ingressCampus{tcpAddress: web.Listener.Addr().String(), udpAddress: udp.LocalAddr().String(), called: make(chan string, 32)}
	r := resolve.NewResolver(campus, "", "", 60,
		client.DomainResources{"owned.campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}},
		map[string][]net.IP{"owned.campus.test": {ip}}, false)
	defer r.Close()
	protection, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8", "::1/128"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[policy.ProtectionPolicy]
	current.Store(&protection)
	r.ProtectionPolicy = current.Load
	d := dial.NewDialer(campus, r, []client.IPResource{
		{IPMin: ip, IPMax: ip, PortMin: 80, PortMax: 80, Protocol: "tcp"},
		{IPMin: ip, IPMax: ip, PortMin: 53, PortMax: 53, Protocol: "udp"},
	}, false)
	d.ProtectionPolicy = current.Load
	d.Upstream = func(context.Context, string, string) (net.Conn, error) {
		originalCalls.Add(1)
		return nil, errors.New("campus ingress must not return to ordinary upstream")
	}
	listeners, err := NewListeners(t.Context(), "127.0.0.1:0", "", d.CampusOnly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.Close()
	_, campusPort, _ := net.SplitHostPort(listeners.listeners[0].Addr().String())
	port, err := strconv.Atoi(campusPort)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixedPort := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	fixture := testmihomo.StartConfiguredBinary(t, "127.0.0.1", true, map[string]any{
		"mixed-port": mixedPort, "mode": "rule",
		"proxies": []any{map[string]any{"name": "JC-CAMPUS", "type": "socks5", "server": "127.0.0.1", "port": port, "udp": true}},
		// Even an overbroad/stale external rule cannot grant campus authority.
		"rules": []string{"MATCH,JC-CAMPUS"},
	})
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
	proxy, err := controller.Proxy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: proxy.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	fixture.WaitReady(t, func() error {
		response, err := httpClient.Get("http://owned.campus.test/readiness")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK || string(body) != "owned campus HTTP" {
			return errors.New("owned campus readiness payload changed")
		}
		return nil
	})
	request := func(address string, allowed bool) {
		t.Helper()
		response, err := httpClient.Get("http://" + address + "/resource")
		if err != nil {
			if allowed {
				t.Fatal("campus HTTP through official Mihomo failed", address, err)
			}
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if !allowed || err != nil || response.StatusCode != 200 || string(data) != "owned campus HTTP" {
			t.Fatal("campus ingress crossed its resource or payload boundary", address, response.StatusCode, err)
		}
	}
	for _, address := range []string{"owned.campus.test", "203.0.113.7"} {
		request(address, true)
	}
	if webRequests.Load() != 3 {
		t.Fatal("campus web peer did not receive both authorized requests")
	}
	for _, address := range []string{"203.0.113.7:81", "203.0.113.8", "unknown.campus.test", "[2001:db8::7]", listeners.listeners[0].Addr().String()} {
		request(address, false)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "udp", "203.0.113.7:53")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	for _, payload := range [][]byte{[]byte("owned campus UDP"), {}} {
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			conn.Close()
			t.Fatal("campus UDP send failed", err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			conn.Close()
			t.Fatal("campus UDP did not reach the owned peer", err)
		}
	}
	conn.Close()
	nextProtection, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8", "::1/128", "203.0.113.7/32"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	current.Store(&nextProtection)
	request("owned.campus.test", false)
	request("203.0.113.7", false)
	if webRequests.Load() != 3 || originalCalls.Load() != 0 {
		t.Fatal("denied campus ingress reached a peer or returned to Clash", webRequests.Load(), originalCalls.Load())
	}
	current.Store(&protection)
	request("owned.campus.test", true)
	if webRequests.Load() != 4 {
		t.Fatal("withdrawing protection did not restore the authorized campus route")
	}
	listeners.Close()
	var actual []string
	for len(campus.called) != 0 {
		actual = append(actual, <-campus.called)
	}
	if len(actual) != 5 || actual[0] != "tcp:203.0.113.7:80" || actual[1] != actual[0] || actual[2] != actual[0] || actual[3] != "udp:203.0.113.7:53" || actual[4] != actual[0] {
		t.Fatal("campus peer observed an unauthorized actual destination", actual)
	}
}
