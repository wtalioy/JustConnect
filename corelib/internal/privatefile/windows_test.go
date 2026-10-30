//go:build windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOpenRestrictsWindowsAccess(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	open := Open
	for _, existing := range []bool{false, true} {
		state := "new"
		if existing {
			state = "existing"
		}
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-key")
			if existing {
				if err := os.WriteFile(path, []byte("old secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				public, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
				if err != nil {
					t.Fatal(err)
				}
				dacl, _, err := public.DACL()
				if err != nil {
					t.Fatal(err)
				}
				if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
					nil, nil, dacl, nil); err != nil {
					t.Fatal(err)
				}
			}
			file, err := open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			control, _, err := sd.Control()
			if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
				t.Fatalf("private file inherits permissions: %s (error: %v)", sd.String(), err)
			}
			dacl, _, err := sd.DACL()
			if err != nil || dacl == nil || dacl.AceCount != 1 {
				t.Fatalf("want exactly one access entry: %s (error: %v)", sd.String(), err)
			}
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, 0, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
				ace.Header.AceFlags != 0 ||
				uint32(ace.Mask)&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ ||
				uint32(ace.Mask)&windows.FILE_GENERIC_WRITE != windows.FILE_GENERIC_WRITE ||
				!windows.EqualSid(sid, user.User.Sid) {
				t.Fatalf("private file grants access beyond the current user: %s", sd.String())
			}
		})
	}
	t.Run("permission-denied", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private-key")
		const content = "must not truncate when permissions cannot be secured"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		denied, err := windows.SecurityDescriptorFromString(
			"D:P(D;;0x2;;;" + user.User.Sid.String() + ")(A;;FA;;;" + user.User.Sid.String() + ")")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := denied.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
		file, err := open(path)
		if err == nil {
			_ = file.Close()
			t.Fatal("private file opened despite denied write access")
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("want access denied, got %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			t.Fatalf("failed open changed the original file: %q (error: %v)", data, err)
		}
	})
}
