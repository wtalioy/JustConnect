//go:build windows

package networkhelper

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/policy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// MS-GPNRPT 2.2.2: local rules; a managed table must not be created or overwritten.
const localDNSPolicy = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
const managedDNSPolicy = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
const genericDNSServers = 0x8 // MS-GPNRPT ConfigOptions: enable the generic DNS option.

var deleteRegistryKey = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtDeleteKey")

type DNSRule struct {
	ID      string   `json:"id"`
	Marker  string   `json:"marker"`
	Domains []string `json:"domains"`
	Server  string   `json:"server"`
}

func (r DNSRule) valid() bool {
	for _, value := range []string{r.ID, r.Marker} {
		id, err := windows.GUIDFromString(value)
		if err != nil || id == (windows.GUID{}) || id.String() != value {
			return false
		}
	}
	server, err := netip.ParseAddr(r.Server)
	if err != nil || !server.Is4() || !server.IsGlobalUnicast() || server.String() != r.Server || len(r.Domains) == 0 {
		return false
	}
	rules := make([]policy.NameRule, 0, len(r.Domains))
	seen := make(map[string]bool)
	for _, name := range r.Domains {
		if seen[name] || name == "localhost" || strings.HasSuffix(name, ".localhost") {
			return false
		}
		seen[name] = true
		rules = append(rules, policy.NameRule{Kind: "suffix", Value: name})
	}
	_, err = policy.NewProtectionPolicy(nil, nil, rules, nil)
	return err == nil
}

func NewDNSRule(domains []string, server netip.Addr) (DNSRule, error) {
	id, err := windows.GenerateGUID()
	if err != nil {
		return DNSRule{}, err
	}
	marker, err := windows.GenerateGUID()
	if err != nil {
		return DNSRule{}, err
	}
	result := DNSRule{ID: id.String(), Marker: marker.String(), Domains: slices.Clone(domains), Server: server.String()}
	if !result.valid() {
		return DNSRule{}, windows.ERROR_INVALID_PARAMETER
	}
	return result, nil
}

func (r DNSRule) namespaces() []string {
	names := make([]string, len(r.Domains))
	for i, name := range r.Domains {
		names[i] = "." + name
	}
	return names
}

func (r DNSRule) class() string { return "JustConnect/" + r.Marker }

func dnsKeyOwner(key registry.Key, rule DNSRule) error {
	// The class is created atomically with the key, before any DNS value can be active.
	expected := rule.class()
	class := make([]uint16, len(expected)+1)
	size := uint32(len(class))
	if err := windows.RegQueryInfoKey(windows.Handle(key), &class[0], &size, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		return err
	}
	if windows.UTF16ToString(class) != expected {
		return windows.ERROR_ACCESS_DENIED
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return windows.ERROR_ACCESS_DENIED
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return windows.ERROR_ACCESS_DENIED
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if ok, _, err := getACE.Call(uintptr(unsafe.Pointer(acl)), uintptr(i), uintptr(unsafe.Pointer(&ace))); ok == 0 {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return windows.ERROR_ACCESS_DENIED
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if uint32(ace.Mask)&uint32(windows.KEY_SET_VALUE|windows.KEY_CREATE_SUB_KEY|windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_WRITE|windows.GENERIC_ALL) != 0 && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return windows.ERROR_ACCESS_DENIED
		}
	}
	return nil
}

// Missing values are permitted only because creation intent was durably saved first.
func (r DNSRule) unchanged(key registry.Key) error {
	info, err := key.Stat()
	if err != nil {
		return err
	}
	if info.SubKeyCount != 0 || info.ValueCount > 4 {
		return windows.ERROR_INVALID_DATA
	}
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		switch name {
		case "Version", "ConfigOptions":
			actual, kind, err := key.GetIntegerValue(name)
			expected := uint64(1)
			if name == "ConfigOptions" {
				expected = genericDNSServers
			}
			if err != nil || kind != registry.DWORD || actual != expected {
				return windows.ERROR_INVALID_DATA
			}
		case "GenericDNSServers":
			actual, kind, err := key.GetStringValue(name)
			if err != nil || kind != registry.SZ || actual != r.Server {
				return windows.ERROR_INVALID_DATA
			}
		case "Name":
			actual, kind, err := key.GetStringsValue(name)
			if err != nil || kind != registry.MULTI_SZ || !slices.Equal(actual, r.namespaces()) {
				return windows.ERROR_INVALID_DATA
			}
		default:
			return windows.ERROR_INVALID_DATA
		}
	}
	return nil
}

func createDNSRule(parent registry.Key, rule DNSRule) error {
	if !rule.valid() {
		return windows.ERROR_INVALID_PARAMETER
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, class := windows.StringToUTF16Ptr(rule.ID), windows.StringToUTF16Ptr(rule.class())
	var handle windows.Handle
	var disposition uint32
	status, _, _ := createRegistryKey.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(class)), 0, windows.KEY_ALL_ACCESS|windows.KEY_WOW64_64KEY, uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&disposition)))
	if status != 0 {
		return windows.Errno(status)
	}
	key := registry.Key(handle)
	defer key.Close()
	if err := dnsKeyOwner(key, rule); err != nil {
		return err
	}
	if err := rule.unchanged(key); err != nil {
		return err
	}
	if err := key.SetDWordValue("Version", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("GenericDNSServers", rule.Server); err != nil {
		return err
	}
	if err := key.SetDWordValue("ConfigOptions", genericDNSServers); err != nil {
		return err
	}
	status, _, _ = flushRegistryKey.Call(uintptr(key))
	if status != 0 {
		return windows.Errno(status)
	}
	// Name is the activation point; partial preparation has no matching namespace.
	if err := key.SetStringsValue("Name", rule.namespaces()); err != nil {
		return err
	}
	status, _, _ = flushRegistryKey.Call(uintptr(key))
	if status != 0 {
		return windows.Errno(status)
	}
	return rule.unchanged(key)
}

func removeDNSRule(parent registry.Key, rule DNSRule) error {
	if !rule.valid() {
		return windows.ERROR_INVALID_PARAMETER
	}
	var handle windows.Handle
	err := windows.RegOpenKeyEx(windows.Handle(parent), windows.StringToUTF16Ptr(rule.ID), registryOpenLink, windows.KEY_ALL_ACCESS|windows.KEY_WOW64_64KEY, &handle)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	key := registry.Key(handle)
	defer key.Close()
	if err := dnsKeyOwner(key, rule); err != nil {
		return err
	}
	if err := rule.unchanged(key); err != nil {
		return err
	}
	// Delete the validated kernel object, never a replacement at the same path.
	status, _, _ := deleteRegistryKey.Call(uintptr(handle))
	if int32(status) < 0 {
		return windows.NTStatus(status).Errno()
	}
	status, _, _ = flushRegistryKey.Call(uintptr(parent))
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
