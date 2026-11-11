//go:build darwin

package bridge

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func macFallbackDNS(t *testing.T, last byte) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: socket, NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			reply := new(dns.Msg).SetReply(request)
			for _, q := range request.Question {
				if q.Qtype == dns.TypeA {
					reply.Answer = append(reply.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
						A:   net.IPv4(192, 0, 2, last),
					})
				}
			}
			_ = w.WriteMsg(reply)
		})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return socket.LocalAddr().(*net.UDPAddr).Port
}

func TestNativeMacCoexistence(t *testing.T) {
	input := os.Getenv("JC_NATIVE_MAC_COEXISTENCE")
	if input == "" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("requires the disposable macOS root runtime and actual authorized network fixture")
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(input), &facts); err != nil {
		t.Fatal(err)
	}
	for key, url := range protectedHTTPPeers(t) {
		facts[key] = url
	}
	facts["fallback_dns_ports"] = []int{macFallbackDNS(t, 50), macFallbackDNS(t, 51)}
	data, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JC_NATIVE_MAC_COEXISTENCE", string(data))
	g, output := runNativeTUNHost(t, true)
	const cases = 24
	if bytes.Count(output, []byte("PASS: macOS composed coexistence case ")) != cases ||
		g.authCount.Load() != 2 || g.tcpCount.Load() != 6+4*cases ||
		g.sshCount.Load() != 4+2*cases || g.udpCount.Load() != 4+2*cases+g.dnsUDPPackets.Load() || g.nativeDNSQueries.Load() < 2 {
		t.Fatalf("missing real macOS matrix traffic: auth=%d TCP=%d SSH=%d UDP=%d DNS-A=%d DNS-all=%d questions=%v\n%s", g.authCount.Load(),
			g.tcpCount.Load(), g.sshCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), g.dnsUDPPackets.Load(), g.observedDNSQuestions(), output)
	}
	t.Log(string(output))
}
