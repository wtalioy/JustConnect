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
	Name    policy.NameRule `json:"name"`
	Servers []string        `json:"servers"`
	// Empty preserves a native unscoped resolver's system routing.
	Interface string `json:"interface,omitempty"`
	Listen    string `json:"listen,omitempty"`
	Source    string `json:"source,omitempty"`
	// Default also supplies unmatched/root queries on this explicit native listener.
	Default bool `json:"default,omitempty"`
}

type originalDNSRoute struct {
	OriginalDNSRoute
	requiresSource bool
}

type OriginalDNS struct {
	routes    []originalDNSRoute
	listeners map[string]originalDNSSource
}

type originalDNSSource struct {
	routes   []int
	fallback int
}

type OriginalDNSListener struct {
	Interface string
	Listen    string
}

// NewOriginalDNS validates and copies native resolver routes before a session starts.
// Only plain DNS sources belong here; native encrypted/security policy cannot be downgraded.
func NewOriginalDNS(routes []OriginalDNSRoute) (*OriginalDNS, error) {
	if len(routes) > maxDNSCacheEntries {
		return nil, errors.New("too many original DNS routes")
	}
	compiled := make([]originalDNSRoute, 0, len(routes))
	seen := make(map[policy.NameRule]map[string]bool)
	servers := 0
	for _, route := range routes {
		_, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{route.Name}, nil)
		servers += len(route.Servers)
		if err != nil || len(route.Servers) == 0 || servers > maxDNSCacheEntries {
			return nil, errors.New("invalid original DNS scope")
		}
		if strings.ContainsAny(route.Interface, "\x00\r\n") {
			return nil, errors.New("invalid original DNS interface")
		}
		if route.Default && route.Listen == "" {
			return nil, errors.New("original DNS default requires a native listener")
		}
		for _, server := range route.Servers {
			endpoint, err := netip.ParseAddrPort(server)
			if err != nil || endpoint.Port() == 0 || (!endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback() && !endpoint.Addr().IsLinkLocalUnicast()) {
				return nil, errors.New("original DNS server must be an explicit unicast endpoint")
			}
		}
		if route.Listen != "" {
			endpoint, err := netip.ParseAddrPort(route.Listen)
			if route.Source == "" || strings.ContainsAny(route.Source, "\x00\r\n") || err != nil || !endpoint.Addr().Is4() || endpoint.String() != route.Listen ||
				(!endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback() && !endpoint.Addr().IsLinkLocalUnicast()) {
				return nil, errors.New("original DNS listener must use an assigned IPv4 endpoint")
			}
		}
		source := route.Source
		if route.Listen == "" {
			source = ""
		}
		if previous := seen[route.Name]; previous != nil && (source == "" || previous[""] || previous[source]) {
			return nil, errors.New("duplicate original DNS scope requires distinct native listeners")
		}
		if seen[route.Name] == nil {
			seen[route.Name] = make(map[string]bool)
		}
		seen[route.Name][source] = true
		route.Servers = slices.Clone(route.Servers)
		compiled = append(compiled, originalDNSRoute{OriginalDNSRoute: route})
	}
	listeners := make(map[string]originalDNSSource)
	for index, route := range compiled {
		compiled[index].requiresSource = len(seen[route.Name]) > 1
		if route.Listen != "" {
			group, found := listeners[route.Source]
			if !found {
				group.fallback = index
			} else {
				first := compiled[group.routes[0]]
				if first.Listen != route.Listen {
					return nil, errors.New("one native DNS source requires one listener")
				}
				if route.Default {
					if group.fallback >= 0 && compiled[group.fallback].Default {
						return nil, errors.New("one native DNS listener requires one default")
					}
					group.fallback = index
				} else if (group.fallback < 0 || !compiled[group.fallback].Default) && !slices.Equal(first.Servers, route.Servers) {
					group.fallback = -1
				}
			}
			group.routes = append(group.routes, index)
			listeners[route.Source] = group
		}
	}
	for _, route := range compiled {
		if group, found := listeners[route.Source]; found && compiled[group.routes[0]].Interface != route.Interface {
			return nil, errors.New("one native DNS listener requires one query exit")
		}
	}
	return &OriginalDNS{routes: compiled, listeners: listeners}, nil
}

func (o *OriginalDNS) ListenSources() map[string]OriginalDNSListener {
	result := make(map[string]OriginalDNSListener)
	if o != nil {
		for source, group := range o.listeners {
			route := o.routes[group.routes[0]]
			result[source] = OriginalDNSListener{Interface: route.Interface, Listen: route.Listen}
		}
	}
	return result
}

func (o *OriginalDNS) nativeRoute(source, host string) *originalDNSRoute {
	if o == nil {
		return nil
	}
	group, found := o.listeners[source]
	if !found {
		return nil
	}
	for _, index := range group.routes {
		if o.routes[index].Name.Matches(host) {
			return &o.routes[index]
		}
	}
	// Mixed server lists require a host-confirmed default for unmatched names/root queries.
	if group.fallback < 0 || (host != "" && !(policy.NameRule{Kind: "exact", Value: host}).Matches(host)) {
		return nil
	}
	return &o.routes[group.fallback]
}

func (r *Resolver) exchangeOriginal(ctx context.Context, request *dns.Msg, transport string,
	publish func(context.Context, []netip.Addr, bool) error) (*dns.Msg, error) {
	host := normalizeHostname(request.Question[0].Name)
	if r.OriginalDNS == nil {
		return nil, ErrOriginalDNSRequired
	}
	for _, route := range r.OriginalDNS.routes {
		if !route.Name.Matches(host) {
			continue
		}
		if route.requiresSource {
			return nil, ErrOriginalDNSRequired
		}
		return r.exchangeOriginalRoute(ctx, request, transport, route, publish, true)
	}
	return nil, ErrOriginalDNSRequired
}

func (r *Resolver) exchangeOriginalRoute(ctx context.Context, request *dns.Msg, transport string, route originalDNSRoute,
	publish func(context.Context, []netip.Addr, bool) error, bind bool) (*dns.Msg, error) {
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
		if !bind {
			return reply, nil
		}
		var prepare func([]netip.Addr) error
		if publish != nil {
			prepare = func(addresses []netip.Addr) error { return publish(ctx, addresses, true) }
		}
		_, err = r.bindDNSAnswer(request, reply, prepare, true)
		return reply, err
	}
	return nil, last
}

// Original direction outlives DNS TTL: a lingering capture must never become a campus grant.
// Name protection wins when two names resolve to the same address.
func (r *Resolver) OriginalDNSProtectedIP(ctx context.Context, address netip.Addr) (bool, error) {
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return false, net.ErrClosed
	}
	snapshot, captured := ctx.Value(ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && r.ProtectionPolicy != nil {
		snapshot = r.ProtectionPolicy()
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	protectedIP := false
	for _, binding := range r.dnsBindings[address.Unmap()] {
		if !binding.original {
			continue
		}
		if snapshot == nil {
			return false, ErrOriginalDNSRequired
		}
		allowed, protected := snapshot.CampusNameAllowed(binding.host)
		if !protected {
			return false, ErrOriginalDNSRequired
		}
		protectedIP = protectedIP || !allowed
	}
	return protectedIP, nil
}
