//go:build windows

package networkhelper

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestDNSRuleBoundaries(t *testing.T) {
	for _, domains := range [][]string{nil, {"."}, {"localhost"}, {"example.localhost"}, {"Mixed.example"}, {"trailing.example."}, {"duplicate.example", "duplicate.example"}, {"valid.example", "bad..example"}} {
		if _, err := NewDNSRule(domains, netip.MustParseAddr("192.0.2.53")); err == nil {
			t.Fatal("accepted unsafe namespaces", domains)
		}
	}
	for _, server := range []string{"0.0.0.0", "127.0.0.1", "224.0.0.1", "::1"} {
		if _, err := NewDNSRule([]string{"safe.invalid"}, netip.MustParseAddr(server)); err == nil {
			t.Fatal("accepted unsafe DNS target", server)
		}
	}
	rule, err := NewDNSRule([]string{"safe.invalid"}, netip.MustParseAddr("192.0.2.53"))
	if err != nil {
		t.Fatal(err)
	}
	rule.Marker = rule.Marker[1:]
	if err := createDNSRule(0, rule); !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatal("noncanonical owner reached registry", err)
	}
}

func TestNativeRegistryClassOwnership(t *testing.T) {
	owner, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name := `Software\JustConnect-test-` + owner.String()
	class := "JustConnect/" + owner.String()
	var handle windows.Handle
	var disposition uint32
	status, _, _ := createRegistryKey.Call(uintptr(windows.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(class))), 0, windows.KEY_ALL_ACCESS, 0, uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&disposition)))
	if status != 0 {
		t.Fatal(windows.Errno(status))
	}
	key := registry.Key(handle)
	defer func() {
		if key != 0 {
			_ = key.Close()
		}
	}()
	defer func() {
		if err := registry.DeleteKey(registry.CURRENT_USER, name); err != nil {
			t.Error(err)
		}
	}()
	if disposition != 1 {
		t.Fatal("new native UUID was not newly created")
	}
	for _, reopen := range []bool{false, true} {
		if reopen {
			key.Close()
			key, err = registry.OpenKey(registry.CURRENT_USER, name, registry.READ)
			if err != nil {
				t.Fatal(err)
			}
		}
		data := make([]uint16, len(class)+1)
		size := uint32(len(data))
		if err := windows.RegQueryInfoKey(windows.Handle(key), &data[0], &size, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if windows.UTF16ToString(data) != class {
			t.Fatal("native registry dropped atomic ownership class")
		}
	}
}

func TestProtectedDNSRuleRecovery(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("protected registry mutation requires disposable Windows runner")
	}
	journal, err := OpenJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	rule, err := NewDNSRule([]string{"private.safe.invalid"}, netip.MustParseAddr("192.0.2.53"))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the exact production operations in the private store, not the live DNS table.
	defer func() {
		if err := removeDNSRule(journal.key, rule); err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		if err := createDNSRule(journal.key, rule); err != nil {
			t.Fatal("create/reuse owned native rule", err)
		}
	}
	key, err := registry.OpenKey(journal.key, rule.ID, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if key != 0 {
			_ = key.Close()
		}
	}()
	foreign := rule
	marker, err := windows.GenerateGUID()
	foreign.Marker = marker.String()
	if err != nil {
		t.Fatal(err)
	}
	if err := removeDNSRule(journal.key, foreign); err == nil {
		t.Fatal("different ownership class deleted rule")
	}
	if err := key.SetStringValue("GenericDNSServers", "192.0.2.54"); err != nil {
		t.Fatal(err)
	}
	if err := removeDNSRule(journal.key, rule); err == nil {
		t.Fatal("external DNS value was deleted")
	}
	if got, _, err := key.GetStringValue("GenericDNSServers"); err != nil || got != "192.0.2.54" {
		t.Fatal("refused recovery changed external DNS", got, err)
	}
	if err := key.SetStringValue("GenericDNSServers", rule.Server); err != nil {
		t.Fatal(err)
	}
	if err := key.DeleteValue("Name"); err != nil {
		t.Fatal(err)
	}
	if err := createDNSRule(journal.key, rule); err != nil {
		t.Fatal("partial write-ahead rule did not resume", err)
	}
	if err := removeDNSRule(journal.key, rule); err != nil {
		t.Fatal(err)
	}
	key.Close()
	key = 0
	if err := removeDNSRule(journal.key, rule); err != nil {
		t.Fatal("restoration was not idempotent", err)
	}
}
