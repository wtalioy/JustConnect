package bridge

import (
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/testdns"
)

func startNativeOriginalDNSSource(t *testing.T) func() {
	t.Helper()
	if os.Getenv("JC_NATIVE_ORIGINAL_DNS") != "1" {
		return func() {}
	}
	if runtime.GOOS != "darwin" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("native DNS source requires the disposable macOS fixture")
	}
	marker := os.Getenv("JC_NATIVE_TUN_READY")
	if marker == "" {
		t.Fatal("missing owned native DNS source control directory")
	}
	tcp, udp := testdns.ListenPair(t, os.Getenv("JC_NATIVE_ORIGINAL_DNS_ADDRESS"))
	var mu sync.Mutex
	queries := make(map[string]int)
	t.Cleanup(func() {
		if t.Failed() {
			mu.Lock()
			defer mu.Unlock()
			t.Logf("CHECK: original native DNS requests after cache prewarm: %v", queries)
		}
	})
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		reply.RecursionAvailable = true
		if len(request.Question) != 1 {
			reply.Rcode = dns.RcodeFormatError
		} else {
			question := request.Question[0]
			if question.Name != "host.campus.test." && question.Name != "withdrawn.campus.test." && question.Name != "target.campus.test." {
				reply.Rcode = dns.RcodeRefused
			} else {
				mu.Lock()
				queries[w.LocalAddr().Network()+":"+question.Name+":"+dns.TypeToString[question.Qtype]]++
				mu.Unlock()
				header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
				if question.Qtype == dns.TypeA && question.Name == "withdrawn.campus.test." && w.LocalAddr().Network() == "udp" {
					reply.Truncated = true
				} else if question.Qtype == dns.TypeA {
					reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IPv4(198, 18, 0, 7)}}
					if question.Name != "target.campus.test." {
						reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: net.IPv4(198, 18, 0, 6)})
					}
				} else if question.Qtype == dns.TypeAAAA && question.Name != "target.campus.test." {
					reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::9")}}
				}
			}
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Net: "tcp", Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	data, err := json.Marshal(map[string]string{"endpoint": tcp.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker+".dns-upstream", data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(marker + ".dns-source-ready"); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatal("native DNS source did not become ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
	mu.Lock()
	clear(queries) // The parent prewarmed both names; acceptance must observe fresh requests after redirection.
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		for _, question := range []string{"udp:host.campus.test.:A", "udp:host.campus.test.:AAAA", "tcp:withdrawn.campus.test.:A"} {
			if queries[question] == 0 {
				t.Fatalf("native source bypassed the prepared core or lost TCP/AAAA: %s; queries=%v", question, queries)
			}
		}
		t.Logf("PASS: original native source after cache prewarm, TCP fallback and AAAA: %v", queries)
	}
}
