//go:build linux

package bridge

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNativeCoexistenceHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_TUN_HOST")
	if host == "" || os.Getenv("JC_NATIVE_COEXISTENCE") != "1" {
		t.Skip("requires the installed-helper/private desktop/native Mihomo namespace fixture")
	}
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("data plane must stay unprivileged")
	}
	g := newGateway(t)
	g.resourceIP.Store("198.18.0.6")
	g.nativeDNS.Store(true)
	g.probeDNS.Store(true)
	enableNativeSSH(t, g)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, host, "--tun-gateway", string(configBytes(t, g.config(t)))).CombinedOutput()
	if err != nil {
		t.Fatalf("native coexistence host: %v\n%s", err, output)
	}
	const cases = 12
	const trafficCases = cases + 2 + 1 // Live exclusions/withdrawal and the initial-TUN session.
	if bytes.Count(output, []byte("PASS: native coexistence case ")) != cases ||
		!bytes.Contains(output, []byte("PASS: preexisting application Fake-IP cache survives native takeover")) ||
		!bytes.Contains(output, []byte("PASS: native coexistence initial TUN startup and restoration")) ||
		!bytes.Contains(output, []byte("PASS: native coexistence live exclusions preserve campus capture and ordinary bypass")) ||
		!bytes.Contains(output, []byte("PASS: native coexistence exclusion withdrawal restores ordinary Clash selection")) ||
		g.authCount.Load() != 2 ||
		g.sshCount.Load() != 2*trafficCases ||
		g.tcpCount.Load() != 4*trafficCases ||
		g.udpCount.Load() != 2*trafficCases+g.nativeDNSQueries.Load() ||
		g.nativeDNSQueries.Load() < 1 {
		t.Fatalf("missing actual matrix traffic: auth=%d TCP=%d SSH=%d UDP=%d DNS=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.sshCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	t.Log(string(output))
}
