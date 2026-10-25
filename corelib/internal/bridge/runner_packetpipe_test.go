//go:build windows

package bridge

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/networkhelper/windows/testsupport"
	"golang.org/x/sys/windows"
)

func TestNativeWindowsPacketHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_WINDOWS_PACKET_HOST")
	if host == "" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("Windows Qt/Wintun packet integration runs in the native ABI target")
	}
	dll := os.Getenv("JC_TEST_WINTUN_DLL")
	if os.Getenv("GITHUB_ACTIONS") != "true" || !windows.GetCurrentProcessToken().IsElevated() || !filepath.IsAbs(dll) {
		t.Fatal("requires the verified SDK and an elevated disposable Windows runner")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				t.Fatal(err)
			}
			if prefix.Contains(netip.MustParseAddr("198.18.0.1")) || prefix.Contains(netip.MustParseAddr("198.18.0.6")) {
				t.Fatal("test addresses already belong to an existing interface")
			}
		}
	}
	token, err := testsupport.OrdinaryToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	g := newGateway(t)
	g.resourceIP.Store("198.18.0.6")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	owner, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name := `\\.\pipe\JustConnect-native-packets-` + owner.String() + "-"
	native := os.Getenv("JC_TEST_CPP_WINTUN_BROKER")
	if !filepath.IsAbs(native) {
		t.Fatal("native C++ packet relay is required")
	}
	helper := exec.CommandContext(ctx, native, "--packet-relay", dll, name)
	control, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var helperOutput bytes.Buffer
	helper.Stdout, helper.Stderr = &helperOutput, &helperOutput
	if err = helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if helper.ProcessState == nil {
			_ = helper.Process.Kill()
			_ = helper.Wait()
		}
	}()
	command := exec.CommandContext(ctx, host, "--packet-gateway", string(configBytes(t, g.config(t))), name, strconv.Itoa(helper.Process.Pid))
	command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	command.Env = os.Environ() // Token-based CreateProcess otherwise drops the CI's Qt/runtime DLL paths.
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(control, "%d\n", command.Process.Pid); err != nil {
		cancel()
	}
	_ = control.Close()
	err = command.Wait()
	if err != nil {
		cancel()
	}
	serverErr := helper.Wait()
	if err != nil || serverErr != nil {
		t.Fatalf("actual native Windows packet chain: host=%v helper=%v\n%s\n%s", err, serverErr, output.Bytes(), helperOutput.Bytes())
	}
	if g.authCount.Load() != 2 || g.tcpCount.Load() != 2 || g.udpCount.Load() != 4 {
		t.Fatalf("actual Windows exchanges auth=%d TCP=%d UDP=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), output.Bytes())
	}
	t.Log(output.String())
	t.Log(helperOutput.String())
}
