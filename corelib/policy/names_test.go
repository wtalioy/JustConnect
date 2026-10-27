package policy

import (
	"strings"
	"testing"
)

func TestNameMembershipSeparatesMalformedInputFromProtection(t *testing.T) {
	rule := NameRule{Kind: "suffix", Value: "original.test"}
	p, err := NewProtectionPolicy(nil, nil, []NameRule{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Matches("Host.ORIGINAL.test.") || rule.Matches("other.test") {
		t.Fatal("namespace membership changed canonical matching")
	}
	for _, host := range []string{"", ".", "bad..original.test", "-bad.original.test", "校园.original.test"} {
		if rule.Matches(host) {
			t.Fatal("malformed input selected a native scope", host)
		}
		if allowed, protected := p.CampusNameAllowed(host); allowed || !protected {
			t.Fatal("malformed input bypassed name protection", host)
		}
	}
}

func TestNativeNameBoundariesAndExactCampusExceptions(t *testing.T) {
	rules := []NameRule{{"suffix", "mesh.test"}, {"exact", "only.example"}, {"prefix", "corp"}, {"single_label", ""}}
	choices := []string{"vpn.mesh.test"}
	p, err := NewProtectionPolicy(nil, nil, rules, choices)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Value = "elsewhere.test"
	choices[0] = "other.mesh.test"
	for _, test := range []struct {
		host               string
		allowed, protected bool
	}{
		{"mesh.test", false, true}, {"A.MESH.TEST.", false, true}, {"notmesh.test", true, false},
		{"mesh.test.evil", true, false}, {"only.example", false, true}, {"child.only.example", true, false},
		{"corpabc.anywhere", false, true}, {"xcorp.anywhere", true, false}, {"printer", false, true},
		{"vpn.mesh.test", true, true}, {"child.vpn.mesh.test", false, true}, {"other.mesh.test", false, true},
		{"public.example", true, false},
		{"校园.mesh.test", false, true}, {"host..mesh.test", false, true}, {"127.0.0.1", true, false},
	} {
		allowed, protected := p.CampusNameAllowed(test.host)
		if allowed != test.allowed || protected != test.protected {
			t.Fatalf("%s: %t %t", test.host, allowed, protected)
		}
	}
	for _, rule := range []NameRule{{"suffix", "."}, {"suffix", ""}, {"suffix", "Mesh.test"}, {"suffix", "mesh.test."},
		{"suffix", "a..test"}, {"exact", "127.0.0.1"}, {"exact", "a\x00.test"}, {"suffix", strings.Repeat("a", 64) + ".test"},
		{"prefix", "corp.test"}, {"single_label", "test"}, {"all", ""}, {"suffix", "校园.test"}} {
		if _, err := NewProtectionPolicy(nil, nil, []NameRule{rule}, nil); err == nil {
			t.Fatalf("ambiguous rule accepted: %#v", rule)
		}
	}
	for _, choice := range []string{"outside.test", "*.mesh.test", "VPN.mesh.test"} {
		if _, err := NewProtectionPolicy(nil, nil, []NameRule{{"suffix", "mesh.test"}}, []string{choice}); err == nil {
			t.Fatalf("broad/outside choice accepted: %s", choice)
		}
	}
	large := make([]NameRule, 4097)
	for i := range large {
		large[i] = NameRule{Kind: "suffix", Value: "mesh.test"}
	}
	if _, err := NewProtectionPolicy(nil, nil, large[:4096], nil); err != nil {
		t.Fatal("valid name boundary rejected", err)
	}
	if _, err := NewProtectionPolicy(nil, nil, large, nil); err == nil {
		t.Fatal("oversized name policy accepted")
	}
	choices = make([]string, 4097)
	for i := range choices {
		choices[i] = "vpn.mesh.test"
	}
	if _, err := NewProtectionPolicy(nil, nil, large[:1], choices); err == nil {
		t.Fatal("oversized name choice list accepted")
	}
}
