//go:build windows

package bridge

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestNativeWindowsSessionCoexistence(t *testing.T) {
	nativeWindowsSession(t, false, false, false)
}

func windowsCoexistenceRuntime(t *testing.T) string {
	t.Helper()
	protected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("original-http")) }))
	t.Cleanup(protected.Close)
	addresses, err := net.DefaultResolver.LookupIPAddr(t.Context(), "github.com")
	if err != nil {
		t.Fatal(err)
	}
	var target net.IP
	for _, address := range addresses {
		if address.IP.To4() != nil && address.IP.IsGlobalUnicast() && !address.IP.IsPrivate() {
			target = address.IP
			break
		}
	}
	if target == nil {
		t.Fatal("no actual public IPv4 HTTP peer")
	}
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: target, Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	source := connection.LocalAddr().(*net.UDPAddr).IP
	connection.Close()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var original string
	for _, iface := range interfaces {
		values, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			ip, _, err := net.ParseCIDR(value.String())
			if err == nil && ip.Equal(source) {
				original = iface.Name
			}
		}
	}
	if original == "" {
		t.Fatal("public peer has no original kernel-selected interface")
	}
	tcp, udp, err := dnslistener.Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		for _, q := range request.Question {
			if q.Name == "github.com." && q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: target})
			}
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	port := testmihomo.ProxyPort(t)
	device := "jcm-coexist-" + rand.Text()
	fixture := testmihomo.StartConfiguredBinary(t, tcp.Addr().String(), true, map[string]any{
		"mixed-port":   port,
		"rules":        []string{"MATCH,DIRECT"},
		"proxy-groups": []any{map[string]any{"name": "GLOBAL", "type": "select", "proxies": []string{"REJECT", "DIRECT"}}},
		"tun": map[string]any{"enable": false, "device": device, "stack": "gvisor", "auto-route": true,
			"auto-detect-interface": true, "inet4-address": []string{"198.18.0.1/30"}, "dns-hijack": []string{}},
	})
	configuration, err := os.ReadFile(fixture.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		transport := &http.Transport{Proxy: nil}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, _ := http.NewRequest(http.MethodPatch, "http://"+fixture.Address+"/configs", bytes.NewBufferString(`{"tun":{"enable":false}}`))
		request.Header.Set("Authorization", "Bearer "+fixture.Secret)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Error("disable the owned proxy TUN", err)
		} else {
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Error("owned proxy refused TUN shutdown", response.Status)
			}
		}
		after, err := os.ReadFile(fixture.Configuration)
		if err != nil || string(after) != string(configuration) {
			t.Error("composed application changed the original proxy source configuration", err)
		}
	})
	data, err := json.Marshal(map[string]any{"controller": fixture.IPC, "pid": fixture.PID, "port": port,
		"original_interface": original, "tun_device": device, "ordinary_address": target.String(), "ordinary_url": "http://github.com/robots.txt",
		"protected_url": protected.URL})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
