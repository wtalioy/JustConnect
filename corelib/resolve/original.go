package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/dialer"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

// OriginalDNSRoute is an already selected native resolver scope. Routes are in
// native precedence order; the host must not infer servers from captured DNS.
type OriginalDNSRoute struct {
	Name            policy.NameRule `json:"name"`
	Servers         []string        `json:"servers"`
	Interface       string          `json:"interface"`
	EgressInterface string          `json:"egress_interface"`
}

type originalDNSRoute struct {
	OriginalDNSRoute
	scope policy.ProtectionPolicy
}

type OriginalDNS struct{ routes []originalDNSRoute }

var ErrOriginalDNSConflict = errors.New("original DNS answers require different network exits")

// NewOriginalDNS validates and copies native resolver routes before a session starts.
// Only plain DNS sources belong here; native encrypted/security policy cannot be downgraded.
func NewOriginalDNS(routes []OriginalDNSRoute) (*OriginalDNS, error) {
	if len(routes) > maxDNSCacheEntries {
		return nil, errors.New("too many original DNS routes")
	}
	compiled := make([]originalDNSRoute, 0, len(routes))
	seen := make(map[policy.NameRule]bool)
	servers := 0
	for _, route := range routes {
		scope, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{route.Name}, nil)
		servers += len(route.Servers)
		if err != nil || seen[route.Name] || len(route.Servers) == 0 || servers > maxDNSCacheEntries {
			return nil, errors.New("invalid original DNS scope")
		}
		for _, name := range []string{route.Interface, route.EgressInterface} {
			if name == "" || strings.ContainsAny(name, "\x00\r\n") {
				return nil, errors.New("invalid original DNS interface")
			}
		}
		for _, server := range route.Servers {
			endpoint, err := netip.ParseAddrPort(server)
			if err != nil || endpoint.Port() == 0 || (!endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback() && !endpoint.Addr().IsLinkLocalUnicast()) {
				return nil, errors.New("original DNS server must be an explicit unicast endpoint")
			}
		}
		seen[route.Name] = true
		route.Servers = slices.Clone(route.Servers)
		compiled = append(compiled, originalDNSRoute{route, scope})
	}
	return &OriginalDNS{routes: compiled}, nil
}

func (r *Resolver) exchangeOriginal(ctx context.Context, request *dns.Msg, transport string,
	publish func(context.Context, []netip.Addr, bool) error) (*dns.Msg, error) {
	host := normalizeHostname(request.Question[0].Name)
	if r.OriginalDNS == nil {
		return nil, ErrOriginalDNSRequired
	}
	for _, route := range r.OriginalDNS.routes {
		if _, matched := route.scope.CampusNameAllowed(host); !matched {
			continue
		}
		dial := &dialer.Dialer{InterfaceName: route.Interface}
		var last error
		for _, server := range route.Servers {
			reply, err := exchangeDNSPacket(ctx, request, transport, server, dial.DialContext)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				last = err
				continue
			}
			var prepare func([]netip.Addr) error
			if publish != nil {
				prepare = func(addresses []netip.Addr) error { return publish(ctx, addresses, true) }
			}
			_, err = r.bindDNSAnswer(request, reply, prepare, route.EgressInterface)
			return reply, err
		}
		return nil, last
	}
	return nil, ErrOriginalDNSRequired
}

// Original direction outlives DNS TTL: a lingering capture must never become a campus grant.
// Name protection wins when two names resolve to the same address.
func (r *Resolver) OriginalInterfaceForIP(ctx context.Context, address netip.Addr) (string, error) {
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return "", net.ErrClosed
	}
	snapshot, captured := ctx.Value(ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && r.ProtectionPolicy != nil {
		snapshot = r.ProtectionPolicy()
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	var result string
	for _, binding := range r.dnsBindings[address.Unmap()] {
		if binding.originalInterface == "" {
			continue
		}
		if snapshot == nil {
			return "", ErrOriginalDNSRequired
		}
		allowed, protected := snapshot.CampusNameAllowed(binding.host)
		if !protected {
			return "", ErrOriginalDNSRequired
		}
		if allowed {
			continue
		}
		if result != "" && result != binding.originalInterface {
			return "", ErrOriginalDNSConflict
		}
		result = binding.originalInterface
	}
	return result, nil
}
