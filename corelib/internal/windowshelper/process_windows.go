package windowshelper

import (
	"errors"

	"golang.org/x/sys/windows"
)

type ProcessIdentity struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created,string"`
	SID     string `json:"sid"`
}

func processIdentity(handle windows.Handle, pid uint32) (ProcessIdentity, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return ProcessIdentity{}, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return ProcessIdentity{}, err
	}
	defer token.Close()
	account, err := token.GetTokenUser()
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), SID: account.User.Sid.String()}, nil
}

// InspectProcess retains the kernel process object to prevent PID reuse during authorization.
func InspectProcess(pid uint32) (ProcessIdentity, windows.Handle, error) {
	if pid == 0 {
		return ProcessIdentity{}, 0, windows.ERROR_INVALID_PARAMETER
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return ProcessIdentity{}, 0, err
	}
	identity, err := processIdentity(handle, pid)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return ProcessIdentity{}, 0, err
	}
	return identity, handle, nil
}

func (identity ProcessIdentity) Alive() (bool, error) {
	sid, err := windows.StringToSid(identity.SID)
	if err != nil || sid.String() != identity.SID || identity.PID == 0 || identity.Created == 0 {
		return false, windows.ERROR_INVALID_DATA
	}
	actual, handle, err := InspectProcess(identity.PID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)
	if actual != identity {
		return false, nil
	}
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, err
	}
	switch status {
	case uint32(windows.WAIT_TIMEOUT):
		return true, nil
	case windows.WAIT_OBJECT_0:
		return false, nil
	default:
		return false, windows.ERROR_INVALID_DATA
	}
}
