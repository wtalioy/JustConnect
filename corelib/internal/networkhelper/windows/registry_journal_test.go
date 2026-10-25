//go:build windows

package networkhelper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/networkhelper/windows/testsupport"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestJournalSecurity(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		sddl    string
		allowed bool
	}{
		{"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)", true},
		{"O:SYG:SYD:P(A;;KA;;;BA)(A;;KA;;;SY)", true},
		{"O:BAG:SYD:(A;;KA;;;SY)(A;;KA;;;BA)", false},
		{"O:" + user.User.Sid.String() + "G:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)", false},
		{"O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;WD)", false},
		{"O:BAG:SYD:P(A;;KR;;;SY)(A;;KA;;;BA)", false},
		{"O:BAG:SYD:P(A;IO;KA;;;SY)(A;;KA;;;BA)", false},
		{"O:BAG:SYD:P(A;;KA;;;BA)(A;;KA;;;BA)", false},
	} {
		descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if allowed := journalSecurity(descriptor) == nil; allowed != test.allowed {
			t.Fatalf("owner/DACL accepted=%t expected=%t for %s", allowed, test.allowed, test.sddl)
		}
	}
}

func TestProtectedJournal(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("machine journal mutation requires a disposable Windows runner")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("native machine-journal test requires the elevated runner")
	}
	journal, err := OpenJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	owner, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Remove(owner) }()
	data := []byte(`{"phase":"allocated"}`)
	if err = journal.Write(owner, data); err != nil {
		t.Fatal(err)
	}
	if got, err := journal.Read(owner); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("checkpoint read: %q %v", got, err)
	}
	owners, err := journal.Owners()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, value := range owners {
		found = found || value == owner
	}
	if !found {
		t.Fatal("recovery enumeration lost the owned checkpoint")
	}
	for _, bad := range [][]byte{nil, []byte("{broken"), make([]byte, contract.MaxRecordBytes+1)} {
		if err := journal.Write(owner, bad); err == nil {
			t.Fatal("accepted a damaged checkpoint")
		}
		if got, err := journal.Read(owner); err != nil || !bytes.Equal(got, data) {
			t.Fatal("invalid write damaged the previous checkpoint", err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := journal.Read(owner); err != nil || !bytes.Equal(got, data) {
		t.Fatal("new recovery owner could not read the durable checkpoint", err)
	}
	token, err := testsupport.OrdinaryToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestJournalOrdinaryChild$", "-test.timeout=3s")
	command.Env = append(os.Environ(), "JC_TEST_MACHINE_JOURNAL_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary token accessed privileged journal: %v\n%s", err, output)
	}
	if err = journal.Remove(owner); err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Read(owner); !errors.Is(err, registry.ErrNotExist) {
		t.Fatal("removed checkpoint still present", err)
	}
}

func TestJournalOrdinaryChild(t *testing.T) {
	if os.Getenv("JC_TEST_MACHINE_JOURNAL_CHILD") != "1" {
		return
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("journal boundary requires an ordinary token")
	}
	journal, err := OpenJournal()
	if err == nil {
		_ = journal.Close()
		t.Fatal("same-SID ordinary token opened the privileged recovery journal")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("unexpected journal refusal", err)
	}
}

func TestProcessIdentityRejectsReusedOwner(t *testing.T) {
	identity, handle, err := InspectProcess(windows.GetCurrentProcessId())
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if alive, err := identity.Alive(); err != nil || !alive {
		t.Fatal("current native owner not recognized", err)
	}
	identity.Created++
	if alive, err := identity.Alive(); err != nil || alive {
		t.Fatal("PID reuse accepted a different native creation time", err)
	}
	identity.Created--
	identity.SID = "S-1-0-0"
	if alive, err := identity.Alive(); err != nil || alive {
		t.Fatal("different caller SID was adopted", err)
	}
}
