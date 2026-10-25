package windowstest

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// PermitDesktop prepares the disposable runner's desktop for the same ordinary SID.
// It changes no token rights and restores only an unchanged ACL after all children exit.
func PermitDesktop(token windows.Token) (func() error, error) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	station, _, err := user32.NewProc("GetProcessWindowStation").Call()
	if station == 0 {
		return nil, err
	}
	runtime.LockOSThread()
	desktop, _, err := user32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	runtime.UnlockOSThread()
	if desktop == 0 {
		return nil, err
	}
	var releases []func() error
	restore := func() error {
		var result error
		for i := len(releases) - 1; i >= 0; i-- {
			result = errors.Join(result, releases[i]())
		}
		return result
	}
	for _, value := range []uintptr{station, desktop} {
		handle := windows.Handle(value)
		original, err := windows.GetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return nil, errors.Join(err, restore())
		}
		acl, _, err := original.DACL()
		if err != nil {
			return nil, errors.Join(err, restore())
		}
		merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)}}}, acl)
		if err != nil {
			return nil, errors.Join(err, restore())
		}
		if err := windows.SetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, merged, nil); err != nil {
			return nil, errors.Join(err, restore())
		}
		applied, err := windows.GetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			_ = windows.SetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
			return nil, errors.Join(err, restore())
		}
		releases = append(releases, func() error {
			current, err := windows.GetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				return err
			}
			if current.String() != applied.String() {
				return windows.ERROR_BUSY
			}
			err = windows.SetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
			runtime.KeepAlive(original)
			return err
		})
		runtime.KeepAlive(merged)
		runtime.KeepAlive(user)
	}
	return restore, nil
}
