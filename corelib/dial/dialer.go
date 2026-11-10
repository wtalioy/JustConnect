package dial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/policy"

	"github.com/wtalioy/JustConnect/corelib/resolve"
	"github.com/wtalioy/JustConnect/corelib/stack"
)

// ErrACLDenied is returned by DialIPPort when the caller forced VPN routing
// for a destination that the sangfor server
// would not accept. Sending it through the L3 tunnel would cause the server
// to terminate the entire session with cmd 0x08 SHUTDOWN, killing all other
// in-flight connections. Refusing here mirrors what the official EasyConnect
// client does and keeps the tunnel alive.
var ErrACLDenied = errors.New("destination not in sangfor IPResources whitelist (would trigger tunnel SHUTDOWN)")

type AuthenticationOrigin struct {
	Name    string
	Address netip.Addr
}

type Dialer struct {
	ProtectionPolicy       func() *policy.ProtectionPolicy
	OriginalAuthentication AuthenticationOrigin
	// Upstream handles ordinary traffic; protected targets retain their native path.
	Upstream      func() client.DialContextFunc
	stack         stack.Stack
	resolver      *resolve.Resolver
	scopedRanges  []client.IPResource
	privateRanges [][2]netip.Addr
	scopedIndex   *ipresource.Index
	resourceIndex *ipresource.Index
	alwaysUseVPN  bool
}

func dialDirect(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// CampusOnly shares the resource indexes and live policy without an ordinary fallback.
func (d *Dialer) CampusOnly() *Dialer {
	campus := *d
	campus.alwaysUseVPN = true
	return &campus
}

func (d *Dialer) dialOrdinary(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Upstream != nil {
		if upstream := d.Upstream(); upstream != nil {
			if host, ok := ctx.Value(resolve.ContextKeyResolveHost).(string); ok {
				if _, port, err := net.SplitHostPort(address); err == nil {
					address = net.JoinHostPort(host, port)
				}
			}
			return upstream(ctx, network, address)
		}
	}
	return dialDirect(ctx, network, address)
}

// Resolve preserves the same DNS boundary for SOCKS and HTTP/domain dials.
func (d *Dialer) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	if d.resolver != nil {
		if d.alwaysUseVPN {
			return d.resolver.ResolveCampus(ctx, host, true)
		}
		return d.resolver.Resolve(ctx, host)
	}
	if d.alwaysUseVPN {
		return ctx, nil, ErrACLDenied
	}
	if d.ProtectionPolicy != nil {
		if snapshot := d.ProtectionPolicy(); snapshot != nil {
			if allowed, protected := snapshot.CampusNameAllowed(host); protected && allowed {
				return ctx, nil, ErrACLDenied
			}
		}
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, errors.New("native DNS lookup returned no addresses")
	}
	return context.WithValue(ctx, resolve.ContextKeyResolveHost, host), ips[0], nil
}

// DialCampusIPPort refuses fallback: a captured flow must never loop into its TUN.
func (d *Dialer) DialCampusIPPort(ctx context.Context, network, address string) (net.Conn, error) {
	return d.CampusOnly().DialIPPort(ctx, network, address)
}

// DialCampusDNS keeps the server-declared DNS socket in the tunnel while ordinary flows retain IP protection.
func (d *Dialer) DialCampusDNS(ctx context.Context, network, address string) (net.Conn, error) {
	if d.resolver == nil {
		return nil, ErrACLDenied
	}
	endpoint, valid := d.resolver.CampusDNSEndpoint()
	if !valid || address != endpoint.String() {
		return nil, ErrACLDenied
	}
	campus := *d
	campus.alwaysUseVPN, campus.ProtectionPolicy = true, nil
	// This applies only to this fixed DNS connection; query names and answers keep the original policy.
	ctx = context.WithValue(ctx, resolve.ContextKeyProtectionPolicy, (*policy.ProtectionPolicy)(nil))
	return campus.DialIPPort(ctx, network, address)
}

// DialDomainDNS applies the gateway endpoint exception only to the gateway's DNS.
func (d *Dialer) DialDomainDNS(ctx context.Context, network, address string) (net.Conn, error) {
	if d.resolver != nil {
		if endpoint, valid := d.resolver.CampusDNSEndpoint(); valid && endpoint.String() == address {
			return d.DialCampusDNS(ctx, network, address)
		}
	}
	return d.DialCampusIPPort(ctx, network, address)
}

// DialCapturedIPPort also accepts a live campus DNS binding; IP protection still applies.
func (d *Dialer) DialCapturedIPPort(ctx context.Context, network, address string) (net.Conn, error) {
	snapshot, captured := ctx.Value(resolve.ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && d.ProtectionPolicy != nil {
		snapshot = d.ProtectionPolicy()
		ctx = context.WithValue(ctx, resolve.ContextKeyProtectionPolicy, snapshot)
	}
	if d.resolver != nil {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip, err := netip.ParseAddr(host); err == nil {
				original, err := d.resolver.OriginalDNSProtectedIP(ctx, ip)
				if err != nil {
					return nil, err
				}
				if original {
					return nil, policy.ErrProtectedTarget
				}
				if ctx.Value(resolve.ContextKeyDomainResource) == nil {
					if resources := d.resolver.CampusResourcesForIP(ctx, ip); len(resources) != 0 {
						ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resources)
					}
				}
			}
		}
	}
	return d.DialCampusIPPort(ctx, network, address)
}

func (d *Dialer) DialIPPort(ctx context.Context, network, ipAddr string) (net.Conn, error) {
	if d.alwaysUseVPN && network != "tcp" && network != "udp" {
		return nil, ErrACLDenied
	}

	ip, portStr, err := net.SplitHostPort(ipAddr)
	if err != nil {
		return nil, errors.New("Invalid address: " + ipAddr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("Invalid port in address: " + ipAddr)
	}
	address, err := netip.ParseAddr(ip)
	if err != nil {
		if d.alwaysUseVPN {
			return nil, ErrACLDenied
		}
		return nil, errors.New("Invalid address: " + ipAddr)
	}
	address = address.Unmap()
	resource, host, matchedResource := matchContextDomainResource(ctx, network, port)
	useVPN := d.alwaysUseVPN
	if !useVPN {
		useVPN, _ = ctx.Value(resolve.ContextKeyDomainDNS).(bool)
	}
	if address == d.OriginalAuthentication.Address && (host == d.OriginalAuthentication.Name || !matchedResource) {
		if useVPN {
			return nil, policy.ErrProtectedTarget
		}
		return d.dialOrdinary(ctx, network, ipAddr)
	}
	snapshot, captured := ctx.Value(resolve.ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && d.ProtectionPolicy != nil {
		snapshot = d.ProtectionPolicy()
	}
	if snapshot != nil {
		namedCampus := false
		if requestedHost, ok := ctx.Value(resolve.ContextKeyResolveHost).(string); ok {
			if allowed, protected := snapshot.CampusNameAllowed(requestedHost); protected {
				if !allowed {
					if d.alwaysUseVPN {
						return nil, policy.ErrProtectedTarget
					}
					return dialDirect(ctx, network, net.JoinHostPort(requestedHost, portStr))
				}
				namedCampus, useVPN = true, true
			}
		}
		if allowed, scope := snapshot.CampusAllowed(address); !allowed && !namedCampus {
			if useVPN {
				return nil, policy.ErrProtectedTarget
			}
			return dialDirect(ctx, network, ipAddr)
		} else if scope.IsValid() {
			useVPN = true
		}
	}

	// Every campus path, including an explicit choice, still requires server authorization.
	useVPN = useVPN || matchedResource
	// Attach DNS-derived names after checking original IP protection.
	if matchedResource {
		ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resource)
		if host != "" {
			ctx = context.WithValue(ctx, resolve.ContextKeyResolveHost, host)
		}
	}

	if !address.Is4() {
		if useVPN {
			return nil, ErrACLDenied
		}
		return d.dialOrdinary(ctx, network, ipAddr)
	}
	if !matchedResource {
		index := d.scopedIndex
		if useVPN || address.IsPrivate() {
			index = d.resourceIndex
		}
		ip := address.As4()
		if resource, matched := matchIPResourceForTunnel(index, ip[:], network, port); matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyIPResource, resource)
			useVPN = true
			matchedResource = true
		}
	}

	if !useVPN {
		return d.dialOrdinary(ctx, network, ipAddr)
	}
	// Refuse before an ungranted flow can terminate the shared tunnel.
	if !matchedResource {
		return nil, ErrACLDenied
	}
	switch network {
	case "tcp":
		return d.stack.DialTCP(ctx, &net.TCPAddr{IP: address.AsSlice(), Port: port})
	case "udp":
		return d.stack.DialUDP(ctx, &net.UDPAddr{IP: address.AsSlice(), Port: port})
	default:
		return nil, ErrACLDenied
	}
}

func matchContextDomainResource(ctx context.Context, network string, port int) (resource client.DomainResource, host string, matched bool) {
	host, _ = ctx.Value(resolve.ContextKeyResolveHost).(string)
	switch resources := ctx.Value(resolve.ContextKeyDomainResource).(type) {
	case []client.DomainResource:
		resource, matched = matchDomainResourceForTunnel(resources, network, port)
	case client.DomainResource:
		resource, matched = matchDomainResourceForTunnel([]client.DomainResource{resources}, network, port)
	case client.DomainResources:
		if host != "" {
			resource, matched = matchDomainResourceForTunnel(resources[host], network, port)
			return
		}
		for name, candidates := range resources {
			candidate, allowed := matchDomainResourceForTunnel(candidates, network, port)
			if !allowed {
				continue
			}
			if matched {
				if network == "tcp" && candidate.EnableTCPPrefL3 != resource.EnableTCPPrefL3 {
					if candidate.EnableTCPPrefL3 {
						continue
					}
				} else if name >= host {
					continue
				}
			}
			resource, host, matched = candidate, name, true
		}
	}
	return
}

func matchDomainResourceForTunnel(resources []client.DomainResource, network string, port int) (client.DomainResource, bool) {
	if network == "tcp" {
		if resource, ok := client.MatchDomainResourceWhere(resources, network, port, func(resource client.DomainResource) bool {
			return !resource.EnableTCPPrefL3
		}); ok {
			return resource, true
		}
	}
	return client.MatchDomainResource(resources, network, port)
}

func matchIPResourceForTunnel(index *ipresource.Index, target net.IP, network string, port int) (client.IPResource, bool) {
	if network == "tcp" {
		if resource, ok := index.MatchWhere(target, network, port, func(resource client.IPResource) bool {
			return !resource.EnableTCPPrefL3
		}); ok {
			return resource, true
		}
	}
	return index.Match(target, network, port)
}

func (d *Dialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if d.alwaysUseVPN {
			return nil, ErrACLDenied
		}
		return d.dialOrdinary(ctx, network, addr)
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return d.DialIPPort(ctx, network, addr)
	}
	if d.resolver == nil {
		if d.alwaysUseVPN {
			return nil, ErrACLDenied
		}
		if d.ProtectionPolicy != nil {
			if snapshot := d.ProtectionPolicy(); snapshot != nil {
				if allowed, protected := snapshot.CampusNameAllowed(host); protected && allowed {
					return nil, ErrACLDenied
				} else if protected {
					return dialDirect(ctx, network, addr)
				}
			}
		}
		return d.dialOrdinary(ctx, network, addr)
	}
	ctx, ip, err := d.Resolve(ctx, host)
	if err != nil {
		// The resolver owns DNS fallback; a native hostname dial bypasses IP policy.
		return nil, err
	}

	return d.DialIPPort(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (d *Dialer) CaptureIPResources() ([]client.IPResource, [][2]netip.Addr) {
	return d.scopedRanges, d.privateRanges
}

func NewDialer(stack stack.Stack, resolver *resolve.Resolver, ipResources []client.IPResource, alwaysUseVPN bool) *Dialer {
	scopedRanges, privateRanges := ipresource.ScopedRanges(ipResources)
	resourceIndex := ipresource.New(ipResources)
	scopedIndex := resourceIndex
	if len(scopedRanges) != len(ipResources) {
		scopedIndex = ipresource.New(scopedRanges)
	}
	return &Dialer{
		stack:         stack,
		resolver:      resolver,
		scopedRanges:  scopedRanges,
		privateRanges: privateRanges,
		scopedIndex:   scopedIndex,
		resourceIndex: resourceIndex,
		alwaysUseVPN:  alwaysUseVPN,
	}
}
