package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

var ErrProtectedTarget = errors.New("destination belongs to a protected original network")

// ProtectionPolicy records original-network targets and explicit campus choices.
// Server authorization remains the dialer's separate responsibility.
type ProtectionPolicy struct {
	protected   []netip.Prefix
	campus      map[netip.Addr]struct{}
	names       []NameRule
	campusNames map[string]struct{}
}

func NewProtectionPolicy(protected, campus []string, names []NameRule, campusNames []string) (ProtectionPolicy, error) {
	policy := ProtectionPolicy{campus: make(map[netip.Addr]struct{}, len(campus))}
	if err := policy.setNames(names, campusNames); err != nil {
		return ProtectionPolicy{}, err
	}
	for i, value := range protected {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() <= 1 || prefix != prefix.Masked() {
			return ProtectionPolicy{}, fmt.Errorf("invalid protected target prefix at index %d", i)
		}
		policy.protected = append(policy.protected, prefix)
	}
	for i, value := range campus {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return ProtectionPolicy{}, fmt.Errorf("invalid campus address at index %d", i)
		}
		address = address.Unmap()
		if !address.Is4() {
			return ProtectionPolicy{}, fmt.Errorf("campus choice requires an IPv4 address at index %d", i)
		}
		policy.campus[address] = struct{}{}
	}
	slices.SortFunc(policy.protected, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return b.Bits() - a.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})
	policy.protected = slices.Compact(policy.protected)
	return policy, nil
}

// CampusAllowed reports preference, never authorization, and the matching protection scope.
func (p ProtectionPolicy) CampusAllowed(address netip.Addr) (bool, netip.Prefix) {
	if !address.IsValid() {
		return false, netip.Prefix{}
	}
	address = address.Unmap().WithZone("")
	for _, prefix := range p.protected {
		if prefix.Contains(address) {
			_, campus := p.campus[address]
			return campus, prefix
		}
	}
	return true, netip.Prefix{}
}
