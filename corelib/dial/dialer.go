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

type Dialer struct {
	ProtectionPolicy func() *policy.ProtectionPolicy
	stack            stack.Stack
	resolver         *resolve.Resolver
	ipResources      []client.IPResource
	resourceIndex    *ipresource.Index
	alwaysUseVPN     bool
}

func dialDirect(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// DialCampusIPPort refuses fallback: a captured flow must never loop into its TUN.
func (d *Dialer) DialCampusIPPort(ctx context.Context, network, address string) (net.Conn, error) {
	campus := *d
	campus.alwaysUseVPN = true
	return campus.DialIPPort(ctx, network, address)
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
				if resources := d.resolver.CampusResourcesForIP(ctx, ip); len(resources) != 0 {
					ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resources)
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
	useVPN := d.alwaysUseVPN
	snapshot, captured := ctx.Value(resolve.ContextKeyProtectionPolicy).(*policy.ProtectionPolicy)
	if !captured && d.ProtectionPolicy != nil {
		snapshot = d.ProtectionPolicy()
	}
	if snapshot != nil {
		namedCampus := false
		if host, ok := ctx.Value(resolve.ContextKeyResolveHost).(string); ok {
			if allowed, protected := snapshot.CampusNameAllowed(host); protected {
				if !allowed {
					if d.alwaysUseVPN {
						return nil, policy.ErrProtectedTarget
					}
					return dialDirect(ctx, network, net.JoinHostPort(host, portStr))
				}
				namedCampus, useVPN = true, true
			}
		}
		if allowed, scope := snapshot.CampusAllowed(address); !allowed && !namedCampus {
			if d.alwaysUseVPN {
				return nil, policy.ErrProtectedTarget
			}
			return dialDirect(ctx, network, ipAddr)
		} else if scope.IsValid() {
			useVPN = true
		}
	}

	// Every campus path, including an explicit choice, still requires server authorization.
	matchedResource := false

	if res := ctx.Value(resolve.ContextKeyDomainResource); res != nil {
		var resource client.DomainResource
		var matched bool
		switch resources := res.(type) {
		case []client.DomainResource:
			resource, matched = matchDomainResourceForTunnel(resources, network, port)
		case client.DomainResource:
			resource, matched = matchDomainResourceForTunnel([]client.DomainResource{resources}, network, port)
		}
		if matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resource)
			useVPN = true
			matchedResource = true
		}
	}

	if !address.Is4() {
		if useVPN {
			return nil, ErrACLDenied
		}
		return dialDirect(ctx, network, ipAddr)
	}
	target := &net.IPAddr{IP: net.IP(address.AsSlice())}

	if !matchedResource && d.ipResources != nil {
		if resource, matched := matchIPResourceForTunnel(d.resourceIndex, target.IP, network, port); matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyIPResource, resource)
			useVPN = true
			matchedResource = true
		}
	}

	// Refuse before an ungranted flow can terminate the shared tunnel.
	if useVPN && !matchedResource {

		return nil, ErrACLDenied
	}

	if useVPN {
		if network == "tcp" {

			return d.stack.DialTCP(ctx, &net.TCPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else if network == "udp" {

			return d.stack.DialUDP(ctx, &net.UDPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else {

			return nil, ErrACLDenied
		}
	} else {
		return dialDirect(ctx, network, ipAddr)
	}
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
		return dialDirect(ctx, network, addr)
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
				}
			}
		}
		return dialDirect(ctx, network, addr)
	}
	var ip net.IP
	if d.alwaysUseVPN {
		ctx, ip, err = d.resolver.ResolveCampus(ctx, host, true)
	} else {
		ctx, ip, err = d.resolver.Resolve(ctx, host)
	}
	if err != nil {
		// The resolver owns DNS fallback; a native hostname dial bypasses IP policy.
		return nil, err
	}

	return d.DialIPPort(ctx, network, net.JoinHostPort(ip.String(), port))
}

func NewDialer(stack stack.Stack, resolver *resolve.Resolver, ipResources []client.IPResource, alwaysUseVPN bool) *Dialer {
	return &Dialer{
		stack:         stack,
		resolver:      resolver,
		ipResources:   ipResources,
		resourceIndex: ipresource.New(ipResources),
		alwaysUseVPN:  alwaysUseVPN,
	}
}
