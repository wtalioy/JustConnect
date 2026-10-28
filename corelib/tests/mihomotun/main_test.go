//go:build darwin || windows

package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestKernelLoopbackRoute(t *testing.T) {
	name, err := routeInterface(t.Context(), netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagLoopback == 0 {
		t.Fatal("native route query did not return the actual loopback", name, err)
	}
}

func TestRemoteURLRejectsCredentialAndNonTLSInputs(t *testing.T) {
	for _, raw := range []string{"http://example.test/", "https://secret@example.test/", "https://example.test/#secret", "https:///missing-host"} {
		if _, err := remoteURL(raw); err == nil {
			t.Fatal("unsafe public probe URL accepted", raw)
		}
	}
	if _, err := remoteURL("https://example.test/robots.txt"); err != nil {
		t.Fatal(err)
	}
}
