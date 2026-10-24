package dial

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestCapturedDNSAddressRetainsPortNameAndIPProtection(t *testing.T) {
	s := &capturingStack{}
	r := resolve.NewResolver(nil, "", "", 30, client.DomainResources{"campus.test": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}, map[string][]net.IP{"campus.test": {net.IPv4(203, 0, 113, 7)}}, false)
	defer r.Close()
	d := NewDialer(s, r, []client.IPResource{}, false)
	var current *policy.ProtectionPolicy
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return current }
	check := func(network, address string, want error) {
		t.Helper()
		conn, err := d.DialCapturedIPPort(t.Context(), network, address)
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, want) {
			t.Fatalf("%s %s: %v, want %v", network, address, err, want)
		}
	}
	check("tcp", "203.0.113.7:80", ErrACLDenied)
	if _, err := r.ExchangeCampus(t.Context(), new(dns.Msg).SetQuestion("campus.test.", dns.TypeA), "udp", nil, nil); err != nil {
		t.Fatal(err)
	}
	check("tcp", "203.0.113.7:80", nil)
	check("tcp", "203.0.113.7:81", ErrACLDenied)
	check("udp", "203.0.113.7:80", ErrACLDenied)
	if _, err := d.DialCampusIPPort(t.Context(), "tcp", "203.0.113.7:80"); !errors.Is(err, ErrACLDenied) {
		t.Fatal("strict campus upstream used a captured DNS binding", err)
	}
	blocked, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "exact", Value: "campus.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	current = &blocked
	check("tcp", "203.0.113.7:80", ErrACLDenied)
	choice, err := policy.NewProtectionPolicy([]string{"203.0.113.0/24"}, nil, []policy.NameRule{{Kind: "exact", Value: "campus.test"}}, []string{"campus.test"})
	if err != nil {
		t.Fatal(err)
	}
	current = &choice
	check("tcp", "203.0.113.7:80", policy.ErrProtectedTarget)
	selected, err := policy.NewProtectionPolicy([]string{"203.0.113.0/24"}, []string{"203.0.113.7"}, []policy.NameRule{{Kind: "exact", Value: "campus.test"}}, []string{"campus.test"})
	if err != nil {
		t.Fatal(err)
	}
	current = &selected
	check("tcp", "203.0.113.7:80", nil)
	check("tcp", "203.0.113.7:81", ErrACLDenied)
	d.ProtectionPolicy = nil
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return &blocked }
	check("tcp", "203.0.113.7:80", ErrACLDenied)
}
