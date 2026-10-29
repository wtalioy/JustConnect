//go:build windows

package dialer

import (
	"net"
	"testing"
)

func TestNativeInterfaceIndexMatchesLoopbackAndRejectsUnknown(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		index, err := interfaceIndex(iface.Name)
		if err != nil || index != uint32(iface.Index) {
			t.Fatalf("bound interface changed: %d, %v; want %d", index, err, iface.Index)
		}
		found = true
	}
	if !found {
		t.Fatal("native loopback interface missing")
	}
	for _, name := range []string{"", "JustConnect-no-such-interface", "invalid\x00interface"} {
		index, err := interfaceIndex(name)
		if err == nil || index != 0 {
			t.Fatalf("invalid interface %q silently selected an exit: %d, %v", name, index, err)
		}
	}
}
