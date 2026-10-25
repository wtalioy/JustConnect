//go:build windows

package bridge

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeWindowsSessionHost(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python", runner, "--session-host", host)
	command.Env = append(os.Environ(), "JC_WINDOWS_SESSION_CONFIG="+string(configBytes(t, g.config(t))))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual ordinary Windows application session: %v\n%s", err, output)
	}
	if g.authCount.Load() != 2 || g.tcpCount.Load() != 2 || g.nativeDNSQueries.Load() < 2 || g.udpCount.Load() != 4+g.nativeDNSQueries.Load() {
		t.Fatalf("actual application exchanges auth=%d TCP=%d UDP=%d DNS=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), g.nativeDNSQueries.Load(), output)
	}
	t.Log(string(output))
}
