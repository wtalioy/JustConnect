//go:build windows

// Package networkhelper contains the Windows permission helper's recovery state.
package networkhelper

import (
	"encoding/json"
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Machine state is separate from user preferences; every checkpoint is one atomic value.
const registryOpenLink = 8 // REG_OPTION_OPEN_LINK: inspect the key rather than following a registry link.

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var createRegistryKey = advapi.NewProc("RegCreateKeyExW")
var flushRegistryKey = advapi.NewProc("RegFlushKey")
var getACE = advapi.NewProc("GetAce")

type Journal struct {
	mu  sync.Mutex
	key registry.Key
}

func journalSecurity(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil || !descriptor.IsValid() {
		return windows.ERROR_ACCESS_DENIED
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return windows.ERROR_ACCESS_DENIED
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		return windows.ERROR_ACCESS_DENIED
	}
	var admin, system bool
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if ok, _, err := getACE.Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&ace))); ok == 0 {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&^uint8(3) != 0 || uint32(ace.Mask) != windows.KEY_ALL_ACCESS {
			return windows.ERROR_ACCESS_DENIED
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
			if admin {
				return windows.ERROR_ACCESS_DENIED
			}
			admin = true
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			if system {
				return windows.ERROR_ACCESS_DENIED
			}
			system = true
		default:
			return windows.ERROR_ACCESS_DENIED
		}
	}
	if !admin || !system {
		return windows.ERROR_ACCESS_DENIED
	}
	return nil
}

func (j *Journal) protected() error {
	if j.key == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(j.key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return journalSecurity(descriptor)
}

func OpenJournal() (*Journal, error) {
	var handle windows.Handle
	name := windows.StringToUTF16Ptr(contract.StateRegistry)
	access := uint32(windows.KEY_ALL_ACCESS | windows.KEY_WOW64_64KEY)
	err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, name, registryOpenLink, access, &handle)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		descriptor, err := windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)")
		if err != nil {
			return nil, err
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
		var disposition uint32
		status, _, _ := createRegistryKey.Call(uintptr(windows.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(name)), 0, 0, 0, uintptr(access), uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&disposition)))
		if status != 0 {
			return nil, windows.Errno(status)
		}
	} else if err != nil {
		return nil, err
	}
	journal := &Journal{key: registry.Key(handle)}
	if err := journal.protected(); err != nil {
		_ = journal.Close()
		return nil, err
	}
	// Link keys contain this value; an unknown link is never adopted as our store.
	if _, _, err := journal.key.GetValue("SymbolicLinkValue", nil); !errors.Is(err, registry.ErrNotExist) {
		_ = journal.Close()
		return nil, windows.ERROR_ACCESS_DENIED
	}
	return journal, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.key == 0 {
		return nil
	}
	err := j.key.Close()
	j.key = 0
	return err
}

func (j *Journal) Read(owner windows.GUID) ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if owner == (windows.GUID{}) {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	if err := j.protected(); err != nil {
		return nil, err
	}
	size, kind, err := j.key.GetValue(owner.String(), nil)
	if err != nil {
		return nil, err
	}
	if kind != registry.BINARY || size <= 0 || size > contract.MaxRecordBytes {
		return nil, windows.ERROR_INVALID_DATA
	}
	data := make([]byte, size)
	n, kind, err := j.key.GetValue(owner.String(), data)
	if err != nil {
		return nil, err
	}
	if kind != registry.BINARY || n != size || !json.Valid(data) {
		return nil, windows.ERROR_INVALID_DATA
	}
	return data, nil
}

func (j *Journal) Write(owner windows.GUID, data []byte) error {
	if owner == (windows.GUID{}) || len(data) == 0 || len(data) > contract.MaxRecordBytes || !json.Valid(data) {
		return windows.ERROR_INVALID_PARAMETER
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.protected(); err != nil {
		return err
	}
	if err := j.key.SetBinaryValue(owner.String(), data); err != nil {
		return err
	}
	return j.flush()
}

func (j *Journal) Remove(owner windows.GUID) error {
	if owner == (windows.GUID{}) {
		return windows.ERROR_INVALID_PARAMETER
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.protected(); err != nil {
		return err
	}
	if err := j.key.DeleteValue(owner.String()); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return j.flush()
}

func (j *Journal) Owners() ([]windows.GUID, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.protected(); err != nil {
		return nil, err
	}
	names, err := j.key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	owners := make([]windows.GUID, 0, len(names))
	for _, name := range names {
		owner, err := windows.GUIDFromString(name)
		if err != nil || owner == (windows.GUID{}) || owner.String() != name {
			return nil, windows.ERROR_INVALID_DATA
		}
		owners = append(owners, owner)
	}
	return owners, nil
}

func (j *Journal) flush() error {
	if status, _, _ := flushRegistryKey.Call(uintptr(j.key)); status != 0 {
		return windows.Errno(status)
	}
	return nil
}
