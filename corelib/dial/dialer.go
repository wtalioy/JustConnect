package dial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

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
	if d.ProtectionPolicy != nil {
		if snapshot := d.ProtectionPolicy(); snapshot != nil {
			if address, err := netip.ParseAddr(ip); err == nil {
				if allowed, _ := snapshot.CampusAllowed(address); !allowed {
					if d.alwaysUseVPN {
						return nil, policy.ErrProtectedTarget
					}
					return dialDirect(ctx, network, ipAddr)
				}
			}
		}
	}

	useVPN := d.alwaysUseVPN

	// Track whether dst:port matches any sangfor-issued resource. We always
	// run both resource lookups (even if useVPN was already forced true by
	// alwaysUseVPN) so we can enforce the server-side ACL client-side.
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

	address := net.ParseIP(ip).To4()
	if address == nil {
		if useVPN {
			return nil, ErrACLDenied
		}
		return dialDirect(ctx, network, ipAddr)
	}
	target := &net.IPAddr{IP: address}

	if !matchedResource && d.ipResources != nil {
		if resource, matched := matchIPResourceForTunnel(d.resourceIndex, target.IP, network, port); matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyIPResource, resource)
			useVPN = true
			matchedResource = true
		}
	}

	// Client-side ACL enforcement: if alwaysUseVPN forced VPN routing for a
	// dst:port that isn't in the server-issued resource list, sending it
	// upstream causes sangfor to terminate the L3 tunnel (cmd 0x08 SHUTDOWN
	// on the next handshake). The official EasyConnect client filters here
	// via CSClient before traffic ever reaches the tunnel; we do the same.
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

	var ip net.IP
	if ip = net.ParseIP(host); ip == nil {
		if d.resolver == nil || strings.Contains(host, ":") {
			if d.alwaysUseVPN {
				return nil, ErrACLDenied
			}
			return dialDirect(ctx, network, addr)
		}
		if d.alwaysUseVPN {
			ctx, ip, err = d.resolver.ResolveCampus(ctx, host, true)
		} else {
			ctx, ip, err = d.resolver.Resolve(ctx, host)
		}
		if err != nil {
			if d.alwaysUseVPN || ctx.Value(resolve.ContextKeyDomainResource) != nil || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil, err
			}
			return dialDirect(ctx, network, addr)
		}
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
