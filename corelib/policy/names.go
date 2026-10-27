package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// NameRule describes a native namespace, not a server grant or a DNS server.
type NameRule struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 253 || name != strings.ToLower(name) {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func (r NameRule) matches(host string) bool {
	switch r.Kind {
	case "suffix":
		return host == r.Value || strings.HasSuffix(host, "."+r.Value)
	case "exact":
		return host == r.Value
	case "prefix":
		return strings.HasPrefix(host, r.Value)
	case "single_label":
		return !strings.Contains(host, ".")
	}
	return false
}

// Matches reports namespace membership; malformed names are not scope matches.
func (r NameRule) Matches(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return validName(host) && r.matches(host)
}

func (p *ProtectionPolicy) setNames(names []NameRule, campus []string) error {
	if len(names) > 4096 || len(campus) > 4096 {
		return fmt.Errorf("too many name protection entries")
	}
	for i, r := range names {
		switch r.Kind {
		case "suffix", "exact":
			if !validName(r.Value) {
				return fmt.Errorf("invalid name rule at index %d", i)
			}
		case "prefix":
			if !validName(r.Value) || strings.Contains(r.Value, ".") {
				return fmt.Errorf("invalid name prefix at index %d", i)
			}
		case "single_label":
			if r.Value != "" {
				return fmt.Errorf("invalid single-label rule at index %d", i)
			}
		default:
			return fmt.Errorf("unknown name rule at index %d", i)
		}
	}
	p.names = slices.Clone(names)
	p.campusNames = make(map[string]struct{}, len(campus))
	for i, name := range campus {
		if !validName(name) {
			return fmt.Errorf("invalid campus name at index %d", i)
		}
		if _, protected := p.CampusNameAllowed(name); !protected {
			return fmt.Errorf("campus name outside protected namespaces at index %d", i)
		}
		p.campusNames[name] = struct{}{}
	}
	return nil
}

// CampusNameAllowed reports preference; exact campus exceptions still need server authorization.
func (p ProtectionPolicy) CampusNameAllowed(host string) (allowed, protected bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validName(host) {
		if _, err := netip.ParseAddr(host); err == nil {
			return true, false
		}
		// Non-ASCII and malformed names must not bypass an installed namespace policy.
		return false, len(p.names) != 0
	}
	for _, rule := range p.names {
		if rule.matches(host) {
			_, chosen := p.campusNames[host]
			return chosen, true
		}
	}
	return true, false
}
