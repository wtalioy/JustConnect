package bridge

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func originalDNSLoopback(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var loopback string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			loopback = iface.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("no active original loopback interface")
	}
	return loopback
}

func TestProtocolOwnsOriginalDNSListeners(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "startup", true: "ready"}[late], func(t *testing.T) {
			loopback := originalDNSLoopback(t)
			upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			server := &dns.Server{PacketConn: upstream, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				reply := new(dns.Msg).SetReply(request)
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(203, 0, 113, 9)}}
				_ = w.WriteMsg(reply)
			})}
			go func() { _ = server.ActivateAndServe() }()
			<-started
			t.Cleanup(func() { _ = server.Shutdown() })
			g := newGateway(t)
			e := New(RunProtocol)
			h := create(t, e)
			config := g.config(t)
			config.Protection = &ProtectionConfig{Protected: []string{}, Campus: []string{}, ProtectedNames: []policy.NameRule{{Kind: "suffix", Value: "original.test"}}}
			config.Network.OriginalDNS = []resolve.OriginalDNSRoute{{Name: config.Protection.ProtectedNames[0],
				Servers: []string{upstream.LocalAddr().String()}, Interface: loopback, EgressInterface: loopback, Source: loopback, Listen: "127.0.0.1:0"}}
			sources := config.Network.OriginalDNS
			if late {
				config.Network.OriginalDNS = nil
			}
			prepare := func(generation uint64, source []resolve.OriginalDNSRoute) (uint64, Status) {
				data, err := json.Marshal(struct {
					SchemaVersion int                        `json:"schema_version"`
					Generation    uint64                     `json:"generation,string"`
					Sources       []resolve.OriginalDNSRoute `json:"sources"`
				}{ABIVersion, generation, source})
				if err != nil {
					t.Fatal(err)
				}
				return e.PrepareOriginalDNS(h, data)
			}
			var oldGeneration uint64
			for round := 0; round < 2; round++ {
				generation, status := e.Start(h, configBytes(t, config))
				if status != OK {
					t.Fatal(status)
				}
				if starting := next(t, e, h); starting.State != "starting" {
					t.Fatal(starting)
				}
				if value, status := prepare(generation, sources); status != Busy || value != 0 {
					t.Fatal("sources prepared before authentication", value, status)
				}
				authenticate(t, e, h)
				ready := next(t, e, h)
				if ready.State != "ready" {
					t.Fatal(ready)
				}
				readResources := func() resourceSnapshot {
					data, status := e.Resources(h, ready.Generation)
					var value resourcesEnvelope
					if status != OK || json.Unmarshal(data, &value) != nil || value.Generation != ready.Generation {
						t.Fatal("invalid generation-bound original DNS resources", status)
					}
					return value.Resources
				}
				if late {
					if len(readResources().OriginalDNSListeners) != 0 {
						t.Fatal("unprepared sources exposed endpoints")
					}
					for _, mutate := range []func(map[string]any){
						func(value map[string]any) { value["schema_version"] = ABIVersion + 1 },
						func(value map[string]any) { value["sources"] = []resolve.OriginalDNSRoute{} },
						func(value map[string]any) { value["replace"] = true },
					} {
						value := map[string]any{"schema_version": ABIVersion, "generation": strconv.FormatUint(ready.Generation, 10), "sources": sources}
						mutate(value)
						data, err := json.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						if applied, status := e.PrepareOriginalDNS(h, data); status != InvalidArgument || applied != 0 || len(readResources().OriginalDNSListeners) != 0 {
							t.Fatal("invalid preparation changed the source set", applied, status)
						}
					}
					want := InvalidArgument
					if oldGeneration != 0 {
						want = StaleRequest
					}
					if value, status := prepare(oldGeneration, sources); status != want || value != 0 {
						t.Fatal("stale generation prepared sources", value, status)
					}
					bad := append([]resolve.OriginalDNSRoute(nil), sources...)
					bad[0].Interface = "missing-original-interface"
					if value, status := prepare(ready.Generation, bad); status != NetworkFailure || value != 0 || len(readResources().OriginalDNSListeners) != 0 {
						t.Fatal("failed preparation exposed sources", value, status)
					}
					if value, status := prepare(ready.Generation, sources); status != OK || value != ready.Generation {
						t.Fatal("ready preparation", value, status)
					}
				}
				if value, status := prepare(ready.Generation, sources); status != Busy || value != 0 {
					t.Fatal("source set was not sealed", value, status)
				}
				address := readResources().OriginalDNSListeners[loopback]
				endpoint, err := netip.ParseAddrPort(address)
				if err != nil || endpoint.Port() == 0 || !endpoint.Addr().IsLoopback() {
					t.Fatal("session did not publish its actual prepared DNS endpoint", address, err)
				}
				exerciseProtocolTUN(t, e, h, ready.Generation)
				if value, status := prepare(ready.Generation, sources); status != Busy || value != 0 {
					t.Fatal("attached device allowed source replacement", value, status)
				}
				reply, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(t.Context(), new(dns.Msg).SetQuestion("host.original.test.", dns.TypeA), address)
				if err != nil || len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
					t.Fatal("actual protocol session did not forward through original DNS", reply, err)
				}
				resources := readResources()
				if len(resources.OriginalDNSRecords["host.original.test"]) != 1 || resources.OriginalDNSRecords["host.original.test"][0] != "203.0.113.9" || len(resources.DNSRecords["host.original.test"]) != 0 {
					t.Fatal("original listener records leaked into campus DNS grants")
				}
				if oldGeneration != 0 {
					if _, status := e.Resources(h, oldGeneration); status != StaleRequest {
						t.Fatal("old generation retained DNS listener authority", status)
					}
				}
				if e.Stop(h, 3000) != OK {
					t.Fatal("stop did not join original DNS listeners")
				}
				if event := next(t, e, h); event.Type != "terminal" || event.Status != Cancelled {
					t.Fatal(event)
				}
				if _, status := e.Resources(h, ready.Generation); status != StaleRequest {
					t.Fatal("stopped session exposed native DNS endpoint", status)
				}
				if value, status := prepare(ready.Generation, sources); status != StaleRequest || value != 0 {
					t.Fatal("stopped generation prepared original sources", value, status)
				}
				tcp, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatal("protocol stop retained original DNS TCP socket", err)
				}
				tcp.Close()
				udp, err := net.ListenPacket("udp4", address)
				if err != nil {
					t.Fatal("protocol stop retained original DNS UDP socket", err)
				}
				udp.Close()
				oldGeneration = ready.Generation
			}
		})
	}
}

func TestNativeOriginalDNSPreparationHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_ORIGINAL_DNS_HOST")
	if host == "" {
		t.Skip("set by formal Qt original DNS preparation test")
	}
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	g := newGateway(t)
	config := g.config(t)
	loopback := originalDNSLoopback(t)
	config.Network.OriginalDNS = []resolve.OriginalDNSRoute{{Name: policy.NameRule{Kind: "suffix", Value: "original.test"},
		Servers: []string{upstream.LocalAddr().String()}, Interface: loopback, EgressInterface: loopback, Source: loopback, Listen: "127.0.0.1:0"}}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, host, "--original-dns-gateway", string(configBytes(t, config))).CombinedOutput()
	if err != nil {
		t.Fatalf("native original DNS host: %v\n%s", err, output)
	}
	if g.authCount.Load() != 1 || !strings.Contains(string(output), "PASS: Qt/C ABI ready DNS preparation") {
		t.Fatalf("missing actual authentication/preparation: auth=%d\n%s", g.authCount.Load(), output)
	}
	t.Log(string(output))
}
