package underlay

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/testdns"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestOfficialMihomoRealDNSControlTLS(t *testing.T) {
	tcp, udp := testdns.ListenPair(t, "127.0.0.1")
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		for _, q := range request.Question {
			h := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 37}
			if q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: h, A: net.ParseIP("127.0.0.1")})
			} else if q.Qtype == dns.TypeAAAA {
				reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: h, AAAA: net.ParseIP("::1")})
			}
		}
		w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		go server.ActivateAndServe()
		t.Cleanup(func() { server.Shutdown() })
	}
	for _, ipc := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "ipc"}[ipc], func(t *testing.T) {
			fixture := testmihomo.StartBinary(t, tcp.Addr().String(), ipc)
			processes, err := mihomo.Processes(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var controller *mihomo.Client
			for _, process := range processes {
				if process.PID == fixture.PID {
					// Mihomo starts its TCP and native IPC listeners asynchronously.
					deadline := time.Now().Add(5 * time.Second)
					for {
						controller, err = mihomo.Inspect(t.Context(), process)
						if err == nil || time.Now().After(deadline) {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					break
				}
			}
			if err != nil || controller == nil || controller.TunEnabled {
				t.Fatalf("official owned controller discovery failed: %v", err)
			}
			query := new(dns.Msg).SetQuestion("fake.example.test.", dns.TypeA)
			var fake *dns.Msg
			deadline := time.Now().Add(5 * time.Second)
			for {
				fake, _, err = (&dns.Client{Timeout: time.Second}).ExchangeContext(t.Context(), query, fixture.DNS)
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil || len(fake.Answer) != 1 {
				t.Fatalf("official Fake-IP DNS listener: %v %v", fake, err)
			}
			address, ok := fake.Answer[0].(*dns.A)
			if !ok || !netip.MustParsePrefix("198.19.0.0/16").Contains(netip.MustParseAddr(address.A.String())) {
				t.Fatalf("test listener did not return its configured Fake-IP range: %v", fake)
			}
			t.Cleanup(controller.Close)
			useController(t, controller)
			systemDials := refuseSystemDial(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" {
					t.Error("original TLS hostname was lost")
				}
				io.WriteString(w, "official runtime control")
			}))
			defer server.Close()
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			dialer, err := New(Options{AutoDetect: false})
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.Proxy, transport.DialContext = nil, dialer.DialContext
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			response, err := client.Get("https://example.com:" + port + "/auth-methods")
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(data) != "official runtime control" || systemDials.Load() != 0 {
				t.Fatalf("official runtime TLS exchange failed: %s %v system fallbacks=%d", data, err, systemDials.Load())
			}
		})
	}
}
