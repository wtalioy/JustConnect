package policy

import (
	"net/netip"
	"testing"
)

func TestProtectionPreservesActualScopesAndExplicitCampusChoices(t *testing.T) {
	policy, err := NewProtectionPolicy([]string{
		"192.168.0.0/16", "192.168.50.0/24", "172.22.8.0/22", "100.100.0.0/24", "fd7a:115c:a1e0::/48", "fe80::/64",
	}, []string{"192.168.50.17", "::ffff:192.168.50.18"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		campus  bool
		scope   string
	}{
		{"192.168.50.10", false, "192.168.50.0/24"},
		{"::ffff:192.168.50.10", false, "192.168.50.0/24"},
		{"192.168.50.17", true, "192.168.50.0/24"},
		{"192.168.50.18", true, "192.168.50.0/24"},
		{"192.168.60.1", false, "192.168.0.0/16"},
		{"172.22.8.9", false, "172.22.8.0/22"},
		{"172.22.12.1", true, ""},
		{"100.100.0.8", false, "100.100.0.0/24"},
		{"100.64.1.1", true, ""},
		{"10.1.2.3", true, ""},
		{"fd7a:115c:a1e0::1", false, "fd7a:115c:a1e0::/48"},
		{"fe80::1%original-interface", false, "fe80::/64"},
		{"2001:db8::1", true, ""},
	} {
		allowed, scope := policy.CampusAllowed(netip.MustParseAddr(test.address))
		if allowed != test.campus || (test.scope == "" && scope.IsValid()) || (test.scope != "" && scope.String() != test.scope) {
			t.Fatalf("%s: campus=%t scope=%v, want %t %s", test.address, allowed, scope, test.campus, test.scope)
		}
	}
	if allowed, _ := policy.CampusAllowed(netip.Addr{}); allowed {
		t.Fatal("invalid address was accepted")
	}
}

func TestProtectionRejectsGlobalExitsAndInvalidOrBroadenedScopes(t *testing.T) {
	for _, prefix := range []string{"invalid", "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0", "192.168.50.1/24", "::ffff:192.168.50.0/120"} {
		if _, err := NewProtectionPolicy([]string{prefix}, nil); err == nil {
			t.Fatalf("ambiguous/global protection %q accepted", prefix)
		}
	}
	for _, choice := range []string{"invalid", "192.168.50.0/24", "fd7a:115c:a1e0::1", "::ffff:192.168.50.17%interface"} {
		if _, err := NewProtectionPolicy(nil, []string{choice}); err == nil {
			t.Fatalf("unsupported campus choice %q accepted", choice)
		}
	}
}

func TestProtectionOwnsItsInputAndCampusChoiceCanBeRemoved(t *testing.T) {
	protected := []string{"192.168.50.0/24"}
	campus := []string{"192.168.50.17"}
	old, err := NewProtectionPolicy(protected, campus)
	if err != nil {
		t.Fatal(err)
	}
	protected[0], campus[0] = "10.0.0.0/8", "10.0.0.1"
	address := netip.MustParseAddr("192.168.50.17")
	if allowed, scope := old.CampusAllowed(address); !allowed || scope.String() != "192.168.50.0/24" {
		t.Fatal("caller changed an existing policy through its input slices")
	}
	restored, err := NewProtectionPolicy([]string{"192.168.50.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, _ := restored.CampusAllowed(address); allowed {
		t.Fatal("removing a campus choice did not restore original-network protection")
	}
}
