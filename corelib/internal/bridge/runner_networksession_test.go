//go:build windows

package bridge

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
	"golang.org/x/sys/windows"
)

func TestNativeWindowsSessionHost(t *testing.T) {
	nativeWindowsSession(t, false, false, false)
}

func TestNativeWindowsSessionFaults(t *testing.T) {
	nativeWindowsSession(t, true, false, false)
}

func TestNativeWindowsSessionPolicy(t *testing.T) {
	nativeWindowsSession(t, false, true, false)
}

func TestNativeWindowsSessionExitChange(t *testing.T) {
	nativeWindowsSession(t, false, false, true)
}

func TestNativeWindowsSessionOriginalDNS(t *testing.T) {
	nativeWindowsSession(t, false, false, false)
}

func windowsOriginalDNSServer(t *testing.T) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var address string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		values, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			ip, _, err := net.ParseCIDR(value.String())
			if err == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
				address = ip.String()
				break
			}
		}
		if address != "" {
			break
		}
	}
	if address == "" {
		t.Fatal("no live IPv4 interface for original DNS fixture")
	}
	tcp, udp, err := dnslistener.Listen(t.Context(), net.JoinHostPort(address, "53"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close(); udp.Close() })
	count := new(atomic.Int32)
	defaultQueries := new(atomic.Int32)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		reply.RecursionAvailable = true
		if len(request.Question) != 1 {
			reply.Rcode = dns.RcodeRefused
		} else if name := request.Question[0].Name; name == "host.campus.test." && request.Question[0].Qtype == dns.TypeA {
			count.Add(1)
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "host.campus.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 9)}}
		} else if strings.HasPrefix(name, "outside-") && strings.HasSuffix(name, ".original.test.") && request.Question[0].Qtype == dns.TypeA {
			defaultQueries.Add(1)
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 77)}}
		} else if name != "host.campus.test." && !(strings.HasPrefix(name, "outside-") && strings.HasSuffix(name, ".original.test.")) {
			reply.Rcode = dns.RcodeRefused
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
	return address, count, defaultQueries
}

func nativeWindowsSession(t *testing.T, faults, policy, exitChange bool) {
	t.Helper()
	host := os.Getenv("JC_NATIVE_WINDOWS_SESSION_HOST")
	if host == "" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("Windows application/native helper integration runs in the native ABI target")
	}
	runner := os.Getenv("JC_NATIVE_WINDOWS_HELPER_RUNNER")
	if !filepath.IsAbs(host) || !filepath.IsAbs(runner) || !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("requires the built application host and an elevated disposable runner")
	}
	g := newGateway(t)
	g.resourceIP.Store("198.18.0.6")
	g.nativeDNS.Store(true)
	g.probeDNS.Store(true)
	g.originalDNSName.Store(t.Name() == "TestNativeWindowsSessionOriginalDNS")
	enableNativeSSH(t, g)
	var original *nativeOriginalPeer
	if policy {
		original = startWindowsOriginalPeer(t, g)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python", runner, "--session-host", host)
	command.Env = append(os.Environ(), "JC_WINDOWS_SESSION_CONFIG="+string(configBytes(t, g.config(t))))
	command.Env = append(command.Env, "JC_WINDOWS_SESSION_POLICY="+strconv.FormatBool(policy))
	command.Env = append(command.Env, "JC_WINDOWS_SESSION_EXIT_CHANGE="+strconv.FormatBool(exitChange))
	var originalQueries, defaultQueries *atomic.Int32
	if t.Name() == "TestNativeWindowsSessionOriginalDNS" {
		address, count, defaults := windowsOriginalDNSServer(t)
		originalQueries, defaultQueries = count, defaults
		command.Env = append(command.Env, "JC_WINDOWS_SESSION_ORIGINAL_DNS_SERVER="+address)
	}
	rounds := int32(2)
	if faults {
		command.Env = append(command.Env, "JC_WINDOWS_SESSION_FAULTS=true")
		rounds = 3
	} else {
		command.Env = append(command.Env, "JC_WINDOWS_SESSION_FAULTS=false")
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual ordinary Windows application session: %v; auth=%d TCP=%d UDP=%d DNS=%d\n%s", err, g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	if g.authCount.Load() != rounds || g.tcpCount.Load() != 4*rounds || g.sshCount.Load() != 2*rounds || g.nativeDNSQueries.Load() < rounds || g.udpCount.Load() != 4*rounds+g.nativeDNSQueries.Load() {
		t.Fatalf("actual application exchanges auth=%d TCP=%d UDP=%d DNS=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	if original != nil && (original.tcp.Load() != 2*rounds || original.udp.Load() != 4*rounds) {
		t.Fatalf("same-IP original exchanges TCP=%d UDP=%d\n%s", original.tcp.Load(), original.udp.Load(), output)
	}
	if original != nil && (original.nonCampusTCP.Load() != rounds || original.nonCampusUDP.Load() != 2*rounds) {
		t.Fatalf("non-campus original exchanges TCP=%d UDP=%d\n%s", original.nonCampusTCP.Load(), original.nonCampusUDP.Load(), output)
	}
	if originalQueries != nil && originalQueries.Load() < 6 {
		t.Fatalf("original source was not queried before, during and after both application sessions: %d\n%s", originalQueries.Load(), output)
	}
	if defaultQueries != nil && defaultQueries.Load() < 6 {
		t.Fatalf("native root provider did not answer fresh unmatched queries before, during and after both sessions: %d\n%s", defaultQueries.Load(), output)
	}
	t.Log(string(output))
}
