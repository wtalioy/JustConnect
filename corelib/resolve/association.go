package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

var ErrCampusDNSCapacity = errors.New("campus DNS address binding capacity reached")

type dnsBinding struct {
	host     string
	expires  time.Time
	original bool
}

// CampusDNSRecords reads the same live bindings used to authorize transparent traffic.
func (r *Resolver) CampusDNSRecords() map[string][]string {
	return r.dnsRecords(false)
}

// Original direction remains observable while the session still owns its binding.
func (r *Resolver) OriginalDNSRecords() map[string][]string {
	return r.dnsRecords(true)
}

func (r *Resolver) dnsRecords(original bool) map[string][]string {
	if r.resolutionClosed.Load() {
		return nil
	}
	r.cacheMu.RLock()
	var result map[string][]string
	now := time.Now()
	for address, bindings := range r.dnsBindings {
		var text string
		for _, binding := range bindings {
			if binding.original != original || (!original && !binding.expires.After(now)) {
				continue
			}
			if result == nil {
				result = make(map[string][]string)
			}
			if text == "" {
				text = address.String()
			}
			result[binding.host] = append(result[binding.host], text)
		}
	}
	r.cacheMu.RUnlock()
	for host := range result {
		slices.Sort(result[host])
		result[host] = slices.Compact(result[host])
	}
	return result
}

func (r *Resolver) bindCampusAnswer(request, reply *dns.Msg, publish func([]netip.Addr) error) ([]netip.Addr, error) {
	return r.bindDNSAnswer(request, reply, publish, false)
}

func (r *Resolver) bindDNSAnswer(request, reply *dns.Msg, publish func([]netip.Addr) error, original bool) ([]netip.Addr, error) {
	if request.Question[0].Qtype != dns.TypeA || reply.Rcode != dns.RcodeSuccess || reply.Truncated {
		return nil, nil
	}
	host := normalizeHostname(request.Question[0].Name)
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
			return nil, ErrInvalidDNSResponse
		}
		seen[name] = true
		target := ""
		for _, record := range records[name] {
			if alias, ok := record.(*dns.CNAME); ok {
				next := normalizeHostname(alias.Target)
				if next == "" || (target != "" && next != target) {
					return nil, ErrInvalidDNSResponse
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
					return nil, ErrInvalidDNSResponse
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
		return nil, nil
	}
	lifetime := r.dnsTTL
	result := make([]netip.Addr, 0, len(addresses))
	for address, ttl := range addresses {
		result = append(result, address)
		lifetime = min(lifetime, ttl)
	}
	slices.SortFunc(result, netip.Addr.Compare)
	if publish != nil {
		if err := publish(result); err != nil {
			return nil, err
		}
	}
	if !original && !r.domainIndex.Contains(host) {
		return result, nil
	}
	if err := r.storeDNSBindings(host, addresses, original); err != nil {
		return nil, err
	}
	if !original {
		// Downstream caches must not outlive the authorization created for this answer.
		for _, record := range reply.Answer {
			if record.Header().Class != dns.ClassINET || !seen[normalizeHostname(record.Header().Name)] {
				continue
			}
			switch record.(type) {
			case *dns.A, *dns.CNAME, *dns.RRSIG:
				record.Header().Ttl = min(record.Header().Ttl, lifetime)
			}
		}
	}
	return result, nil
}

func (r *Resolver) storeDNSBindings(host string, addresses map[netip.Addr]uint32, original bool) error {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now()
	// A campus refresh must not erase the original direction needed after withdrawal.
	matches := func(binding dnsBinding) bool {
		return binding.host == host && binding.original == original
	}
	needed := func() int {
		n := 0
		for address := range addresses {
			if !slices.ContainsFunc(r.dnsBindings[address], matches) {
				n++
			}
		}
		return n
	}
	if r.dnsBindingCount+len(addresses) > maxDNSCacheEntries && r.dnsBindingCount+needed() > maxDNSCacheEntries {
		for address, bindings := range r.dnsBindings {
			kept := bindings[:0]
			for _, binding := range bindings {
				if binding.original || binding.expires.After(now) {
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
		r.dnsBindings = make(map[netip.Addr][]dnsBinding)
	}
	for address, ttl := range addresses {
		// A zero-TTL answer needs a bounded window for the host's first connection.
		binding := dnsBinding{host: host, expires: now.Add(time.Duration(max(ttl, 1)) * time.Second), original: original}
		rows := r.dnsBindings[address]
		if index := slices.IndexFunc(rows, matches); index >= 0 {
			rows[index] = binding
			continue
		}
		r.dnsBindings[address] = append(rows, binding)
		r.dnsBindingCount++
	}
	return nil
}

// CampusResourcesForIP keeps the name with each live grant for the tunnel authorization request.
func (r *Resolver) CampusResourcesForIP(ctx context.Context, address netip.Addr) client.DomainResources {
	resources, _ := r.campusResources(ctx, address, "", "")
	return resources
}

func (r *Resolver) CampusResourcesExcludingName(ctx context.Context, address netip.Addr, name string) client.DomainResources {
	resources, _ := r.campusResources(ctx, address, "", normalizeHostname(name))
	return resources
}

func (r *Resolver) campusResources(ctx context.Context, address netip.Addr, name, excluded string) (client.DomainResources, uint32) {
	if r.resolutionClosed.Load() {
		return nil, 0
	}
	snapshot, captured := ctx.Value(ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && r.ProtectionPolicy != nil {
		snapshot = r.ProtectionPolicy()
	}
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	var result client.DomainResources
	ttl := r.dnsTTL
	now := time.Now()
	for _, binding := range r.dnsBindings[address.Unmap()] {
		if (name != "" && binding.host != name) || (excluded != "" && binding.host == excluded) {
			continue
		}
		if !binding.expires.After(now) {
			continue
		}
		if binding.original {
			continue
		}
		if snapshot != nil {
			if allowed, protected := snapshot.CampusNameAllowed(binding.host); protected && !allowed {
				return nil, 0
			}
		}
		if _, resources, granted := r.domainIndex.Match(binding.host); granted {
			if result == nil {
				result = make(client.DomainResources)
			}
			result[binding.host] = resources
			if name != "" {
				ttl = min(ttl, uint32(max(binding.expires.Sub(now)/time.Second, 0)))
			}
		}
	}
	return result, ttl
}

// AliasCampusAnswer presents a live campus binding without taking over its shared original IP.
func (r *Resolver) AliasCampusAnswer(ctx context.Context, request, reply *dns.Msg, address, alias netip.Addr) *dns.Msg {
	if request == nil || reply == nil || len(request.Question) != 1 {
		return reply
	}
	host := normalizeHostname(request.Question[0].Name)
	if host == "" {
		return reply
	}
	resources, ttl := r.campusResources(ctx, address, host, "")
	if len(resources) == 0 {
		return reply
	}
	for _, record := range reply.Answer {
		if answer, ok := record.(*dns.A); ok && answer.A.Equal(net.IP(address.AsSlice())) {
			copy := reply.Copy()
			copy.AuthenticatedData = false
			kept := copy.Answer[:0]
			for _, record := range copy.Answer {
				if signature, ok := record.(*dns.RRSIG); ok && signature.TypeCovered == dns.TypeA {
					continue
				}
				if answer, ok := record.(*dns.A); ok && answer.A.Equal(net.IP(address.AsSlice())) {
					answer.A = net.IP(alias.AsSlice())
					answer.Hdr.Ttl = min(answer.Hdr.Ttl, ttl)
				}
				kept = append(kept, record)
			}
			copy.Answer = kept
			return copy
		}
	}
	return reply
}
