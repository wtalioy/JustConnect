package resolve

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

var ErrCampusDNSCapacity = errors.New("campus DNS address binding capacity reached")

type campusDNSBinding struct {
	host    string
	expires time.Time
}

func (r *Resolver) bindCampusAnswer(request, reply *dns.Msg) error {
	if request.Question[0].Qtype != dns.TypeA || reply.Rcode != dns.RcodeSuccess || reply.Truncated {
		return nil
	}
	host := normalizeHostname(request.Question[0].Name)
	if _, _, granted := matchDomainResource(r.domainIndex, host); !granted {
		return nil
	}
	records := make(map[string][]dns.RR)
	for _, record := range reply.Answer {
		if record.Header().Class != dns.ClassINET {
			continue
		}
		name := normalizeHostname(record.Header().Name)
		records[name] = append(records[name], record)
	}
	addresses := make(map[netip.Addr]uint32)
	seen := make(map[string]bool)
	name, ttl := host, r.dnsTTL
	for {
		if seen[name] {
			return ErrInvalidDNSResponse
		}
		seen[name] = true
		target := ""
		for _, record := range records[name] {
			if alias, ok := record.(*dns.CNAME); ok {
				next := normalizeHostname(alias.Target)
				if next == "" || (target != "" && next != target) {
					return ErrInvalidDNSResponse
				}
				target = next
				ttl = min(ttl, alias.Hdr.Ttl)
			}
		}
		if target != "" {
			name = target
			continue
		}
		for _, record := range records[name] {
			if answer, ok := record.(*dns.A); ok {
				address, valid := netip.AddrFromSlice(answer.A.To4())
				if !valid {
					return ErrInvalidDNSResponse
				}
				lifetime := min(ttl, answer.Hdr.Ttl)
				if previous, found := addresses[address]; found {
					lifetime = min(previous, lifetime)
				}
				addresses[address] = lifetime
			}
		}
		break
	}
	if len(addresses) == 0 {
		return nil
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now()
	needed := func() int {
		n := 0
		for address := range addresses {
			found := false
			for _, binding := range r.dnsBindings[address] {
				found = found || binding.host == host
			}
			if !found {
				n++
			}
		}
		return n
	}
	if r.dnsBindingCount+needed() > maxDNSCacheEntries {
		for address, bindings := range r.dnsBindings {
			kept := bindings[:0]
			for _, binding := range bindings {
				if binding.expires.After(now) {
					kept = append(kept, binding)
				} else {
					r.dnsBindingCount--
				}
			}
			if len(kept) == 0 {
				delete(r.dnsBindings, address)
			} else {
				r.dnsBindings[address] = kept
			}
		}
		if r.dnsBindingCount+needed() > maxDNSCacheEntries {
			return ErrCampusDNSCapacity
		}
	}
	if r.dnsBindings == nil {
		r.dnsBindings = make(map[netip.Addr][]campusDNSBinding)
	}
	for address, ttl := range addresses {
		// A zero-TTL answer needs a bounded window for the host's first connection.
		binding := campusDNSBinding{host: host, expires: now.Add(time.Duration(max(ttl, 1)) * time.Second)}
		rows := r.dnsBindings[address]
		found := false
		for index := range rows {
			if rows[index].host == host {
				rows[index] = binding
				found = true
				break
			}
		}
		if !found {
			rows = append(rows, binding)
			r.dnsBindingCount++
		}
		r.dnsBindings[address] = rows
	}
	return nil
}

// CampusResourcesForIP only uses live DNS bindings and the caller's current name policy.
func (r *Resolver) CampusResourcesForIP(ctx context.Context, address netip.Addr) []client.DomainResource {
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return nil
	}
	snapshot, captured := ctx.Value(ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && r.ProtectionPolicy != nil {
		snapshot = r.ProtectionPolicy()
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	var result []client.DomainResource
	seen := make(map[string]bool)
	now := time.Now()
	for _, binding := range r.dnsBindings[address.Unmap()] {
		if !binding.expires.After(now) {
			continue
		}
		if snapshot != nil {
			if allowed, protected := snapshot.CampusNameAllowed(binding.host); protected && !allowed {
				return nil
			}
		}
		if pattern, resources, granted := matchDomainResource(r.domainIndex, binding.host); granted && !seen[pattern] {
			seen[pattern] = true
			result = append(result, resources...)
		}
	}
	return result
}
