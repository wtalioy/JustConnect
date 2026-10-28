//go:build windows

package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
	windowsfixture "github.com/wtalioy/JustConnect/corelib/tests/windows"
	"golang.org/x/sys/windows"
)

func TestProtectedWindowsControllerRealDNS(t *testing.T) {
	if input := os.Getenv("JC_TEST_PROTECTED_CONTROLLER"); input != "" {
		if windows.GetCurrentProcessToken().IsElevated() {
			t.Fatal("controller consumer must remain unelevated")
		}
		var fixture testmihomo.Fixture
		if err := json.Unmarshal([]byte(input), &fixture); err != nil {
			t.Fatal(err)
		}
		if handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(fixture.PID)); err != windows.ERROR_ACCESS_DENIED {
			if err == nil {
				windows.CloseHandle(handle)
			}
			t.Fatal("protected controller process query was not denied", err)
		}
		if _, err := os.ReadFile(fixture.Configuration); !errors.Is(err, os.ErrPermission) {
			t.Fatal("protected configuration was readable", err)
		}
		process := ownedProcess(t, fixture.PID)
		if process.Started == 0 || len(process.Args) != 0 || !slices.Contains(process.IPC, fixture.IPC) {
			t.Fatal("protected controller identity or observed IPC missing")
		}
		client, err := Inspect(t.Context(), process)
		if err != nil {
			t.Fatal("ordinary caller could not inspect protected controller", err)
		}
		defer client.Close()
		answer, err := client.Query(t.Context(), dns.Question{Name: "protected-controller.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil || len(answer.Answer) != 1 {
			t.Fatal("protected controller real DNS response", err)
		}
		address, ok := answer.Answer[0].(*dns.A)
		if !ok || !address.A.Equal(net.IPv4(192, 0, 2, 10)) {
			t.Fatal("protected controller changed the original DNS result")
		}
		return
	}
	fixture := testmihomo.StartBinary(t, originalControllerDNS(t), true)
	protectOwnedController(t, fixture)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestProtectedWindowsControllerRealDNS$", "-test.v")
	data, _ := json.Marshal(fixture)
	command.Env = append(os.Environ(), "JC_TEST_PROTECTED_CONTROLLER="+string(data))
	if windows.GetCurrentProcessToken().IsElevated() {
		token, err := windowsfixture.OrdinaryToken()
		if err != nil {
			t.Fatal(err)
		}
		defer token.Close()
		command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	}
	output, err := command.CombinedOutput()
	t.Logf("ordinary consumer: %s", output)
	if err != nil {
		t.Fatal("protected controller ordinary query", err)
	}
}

// Restrict only the owned fixture's objects; no token elevation or system network changes.
func protectOwnedController(t *testing.T, fixture *testmihomo.Fixture) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	process, err := windows.OpenProcess(windows.WRITE_DAC|windows.READ_CONTROL, false, uint32(fixture.PID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(process) })
	originalProcess, err := windows.GetSecurityInfo(process, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	processACL, _, err := originalProcess.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(process, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetSecurityInfo(process, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, processACL, nil); err != nil {
			t.Error("restore owned process permissions", err)
		}
	})
	originalFile, err := windows.GetNamedSecurityInfo(fixture.Configuration, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	fileACL, _, err := originalFile.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(fixture.Configuration, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetNamedSecurityInfo(fixture.Configuration, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, fileACL, nil); err != nil {
			t.Error("restore owned configuration permissions", err)
		}
	})
}
