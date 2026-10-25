//go:build windows

package testutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OrdinaryToken preserves the caller SID with a medium-integrity LUA token.
func OrdinaryToken() (windows.Token, error) {
	var original, restricted windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &original); err != nil {
		return 0, fmt.Errorf("open caller token: %w", err)
	}
	defer original.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	denied := windows.SIDAndAttributes{Sid: admin}
	create := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	const disableMaxPrivilege, luaToken = 0x1, 0x4
	ok, _, err := create.Call(uintptr(original), disableMaxPrivilege|luaToken, 1, uintptr(unsafe.Pointer(&denied)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if ok == 0 {
		return 0, fmt.Errorf("restrict caller token: %w", err)
	}
	medium, err := windows.StringToSid("S-1-16-8192")
	if err == nil {
		label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
		err = windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size())
	}
	if err != nil {
		restricted.Close()
		return 0, fmt.Errorf("limit client integrity: %w", err)
	}
	user, err := restricted.GetTokenUser()
	if err != nil {
		restricted.Close()
		return 0, err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		restricted.Close()
		return 0, err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		restricted.Close()
		return 0, err
	}
	// New child process objects must remain accessible after the administrator SID becomes deny-only.
	defaultACL := struct{ ACL *windows.ACL }{acl}
	if err := windows.SetTokenInformation(restricted, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&defaultACL)), uint32(unsafe.Sizeof(defaultACL))); err != nil {
		restricted.Close()
		return 0, fmt.Errorf("set ordinary child object permissions: %w", err)
	}
	return restricted, nil
}
