package windowshelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/windowstest"
	"golang.org/x/sys/windows"
)

func TestInstallationRequiresTrustedBuildBeforeMachineChanges(t *testing.T) {
	saved := publisherSHA256
	publisherSHA256 = ""
	defer func() { publisherSHA256 = saved }()
	installation, err := PrepareInstallation()
	if installation != nil || (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_NOT_SUPPORTED)) {
		t.Fatal("unconfigured helper entered machine installation", err)
	}
}

func TestTrustedInstallation(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || publisherSHA256 == "" {
		t.Skip("signed installation requires the disposable native validation host")
	}
	installation, err := PrepareInstallation()
	if err != nil {
		t.Fatal("install signed current image", err)
	}
	defer installation.Close()
	directory := filepath.Dir(installation.Image)
	defer func() {
		installation.Close()
		for _, name := range []string{contract.Executable, contract.DriverLibrary, contract.DriverLicense} {
			if err := os.Remove(filepath.Join(directory, name)); err != nil {
				t.Error("remove owned validation payload", err)
			}
		}
		if err := os.Remove(directory); err != nil {
			t.Error("remove owned validation version", err)
		}
	}()
	second, err := PrepareInstallation()
	if err != nil {
		t.Fatal("reuse identical protected payloads", err)
	}
	if second.Image != installation.Image || second.Driver != installation.Driver {
		t.Fatal("identical signed source changed installation identity")
	}
	second.Close()
	token, err := windowstest.OrdinaryToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, installation.Image, "-test.run=^TestInstalledOrdinaryChild$", "-test.timeout=8s")
	command.Env = append(os.Environ(), "JC_TEST_INSTALLED_CHILD=1")
	command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary installed-image boundary: %v\n%s", err, output)
	}
}

func TestInstalledOrdinaryChild(t *testing.T) {
	if os.Getenv("JC_TEST_INSTALLED_CHILD") != "1" {
		return
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("installation boundary requires an ordinary token")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{contract.Executable, contract.DriverLibrary, contract.DriverLicense} {
		path := filepath.Join(filepath.Dir(self), name)
		for _, access := range []uint32{windows.FILE_WRITE_DATA, windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER} {
			handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
			if err == nil {
				windows.CloseHandle(handle)
				t.Fatalf("ordinary token opened installed %s with access %#x", name, access)
			}
			if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("unexpected refusal for %s/access %#x: %v", name, access, err)
			}
		}
	}
	child := filepath.Join(filepath.Dir(self), "unclaimed-child")
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(child), nil); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("ordinary token could create an installed payload", err)
	}
}

func TestInstallerRefusesUserOwnedExistingPayload(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if trustedOwner(user.User.Sid) {
		t.Skip("requires a user SID distinct from machine installation owners")
	}
	directory := t.TempDir()
	data := []byte("untrusted existing payload")
	path := filepath.Join(directory, "existing.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	owner, _, err := current.Owner()
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var replacement *windows.SID
	if !windows.EqualSid(owner, user.User.Sid) {
		_ = windows.CloseHandle(handle)
		handle, err = windows.CreateFile(windows.StringToUTF16Ptr(path), windows.WRITE_OWNER|windows.WRITE_DAC, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		flags |= windows.OWNER_SECURITY_INFORMATION
		replacement = user.User.Sid
	}
	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, flags, replacement, nil, acl, nil)
	_ = windows.CloseHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := installFile(source, path, sha256.Sum256(data)); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("hash equality adopted a user-owned payload", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("refused installation changed an unrelated existing file", err)
	}
}
