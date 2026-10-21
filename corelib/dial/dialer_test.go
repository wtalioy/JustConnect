package dial

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestRequiredCampusPathNeverFallsBack(t *testing.T) {
	for _, call := range []struct {
		name, network, address string
		resolve                bool
	}{
		{"unknown resources", "tcp", "127.0.0.1:9", false},
		{"IPv6", "udp", "[::1]:9", false},
		{"mapped IPv4", "udp", "[::ffff:127.0.0.1]:9", false},
		{"unresolved host", "udp", "localhost:9", false},
		{"unsupported protocol", "unix", "127.0.0.1:9", false},
		{"resolved entry IPv6", "udp", "[::1]:9", true},
	} {
		t.Run(call.name, func(t *testing.T) {
			dialer := &Dialer{stack: &capturingStack{}, alwaysUseVPN: true}
			var conn net.Conn
			var err error
			if call.resolve {
				conn, err = dialer.Dial(t.Context(), call.network, call.address)
			} else {
				conn, err = dialer.DialIPPort(t.Context(), call.network, call.address)
			}
			if conn != nil {
				conn.Close()
			}
			if !errors.Is(err, ErrACLDenied) || conn != nil {
				t.Fatalf("required campus path escaped: connection=%t, error=%v", conn != nil, err)
			}
		})
	}
}

func TestRequiredCampusResolutionFailureNeverUsesPublicResolver(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	var public atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		public.Add(1)
		return nil, errors.New("public DNS is outside the required campus path")
	}}
	resolver := resolve.NewResolver(nil, "", "", 1, nil, nil, false)
	resolver.Close()
	dialer := &Dialer{resolver: resolver, alwaysUseVPN: true}
	conn, err := dialer.Dial(t.Context(), "udp", "unavailable.invalid:9")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, net.ErrClosed) || conn != nil || public.Load() != 0 {
		t.Fatalf("campus DNS failure escaped: public queries=%d, connection=%t, error=%v", public.Load(), conn != nil, err)
	}
}

func TestRequiredCampusPathPreservesAuthorizedResources(t *testing.T) {
	resource := client.IPResource{IPMin: net.IPv4(127, 0, 0, 1), IPMax: net.IPv4(127, 0, 0, 1),
		Protocol: "udp", PortMin: 9, PortMax: 9, AppID: "authorized-udp"}
	for _, address := range []string{"127.0.0.1:9", "[::ffff:127.0.0.1]:9"} {
		stack := &capturingStack{}
		dialer := &Dialer{stack: stack, alwaysUseVPN: true, ipResources: []client.IPResource{resource}, resourceIndex: ipresource.New([]client.IPResource{resource})}
		conn, err := dialer.DialIPPort(t.Context(), "udp", address)
		if conn != nil {
			conn.Close()
		}
		if err != nil || conn != nil || stack.udpCalls != 1 || stack.ipResource.AppID != resource.AppID {
			t.Fatalf("authorized mapped/IPv4 traffic did not use the tunnel: %v", err)
		}
	}
	domains := client.DomainResources{"campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443, AppID: "authorized-domain"}}}
	resolver := resolve.NewResolver(nil, "", "", 1, domains, map[string][]net.IP{"campus.test": {net.IPv4(127, 0, 0, 1)}}, false)
	defer resolver.Close()
	stack := &capturingStack{}
	dialer := &Dialer{stack: stack, resolver: resolver, alwaysUseVPN: true}
	if _, err := dialer.Dial(t.Context(), "tcp", "campus.test:443"); err != nil || stack.domainResource.AppID != "authorized-domain" {
		t.Fatal("domain-only authorization or built-in campus resolution was lost", err)
	}
}

func TestMatchesIPResourcePreservesRangePortAndProtocolRules(t *testing.T) {
	resources := []client.IPResource{{
		IPMin:    net.IPv4(10, 0, 0, 1),
		IPMax:    net.IPv4(10, 0, 0, 10),
		PortMin:  443,
		PortMax:  443,
		Protocol: "tcp",
	}}
	index := ipresource.New(resources)

	tests := []struct {
		name    string
		ip      net.IP
		network string
		port    int
		want    bool
	}{
		{name: "match", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 443, want: true},
		{name: "outside range", ip: net.IPv4(10, 0, 0, 11), network: "tcp", port: 443},
		{name: "wrong port", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 80},
		{name: "wrong protocol", ip: net.IPv4(10, 0, 0, 5), network: "udp", port: 443},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, got := matchIPResourceForTunnel(index, test.ip, test.network, test.port); got != test.want {
				t.Fatalf("matchIPResourceForTunnel() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDialIPPortSelectsMatchingDomainResource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "https"},
		{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "http"},
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyDomainResource, resources)
	dialer := &Dialer{stack: &capturingStack{}, resourceIndex: ipresource.New(nil)}

	_, err := dialer.DialIPPort(ctx, "tcp", "121.194.4.13:443")
	if err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if got := dialer.stack.(*capturingStack).domainResource.AppID; got != "https" {
		t.Fatalf("selected AppID = %q, want https", got)
	}
}

func TestDialIPPortPrefersTCPTunnelResourceOverOverlappingL3Resource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "l3", EnableTCPPrefL3: true},
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "tcp"},
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyDomainResource, resources)
	dialer := &Dialer{stack: &capturingStack{}, resourceIndex: ipresource.New(nil)}

	if _, err := dialer.DialIPPort(ctx, "tcp", "121.194.4.13:443"); err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if got := dialer.stack.(*capturingStack).domainResource.AppID; got != "tcp" {
		t.Fatalf("selected AppID = %q, want tcp", got)
	}
}

func TestDialIPPortCarriesTCPPrefL3IPResource(t *testing.T) {
	resource := client.IPResource{
		IPMin: net.IPv4(10, 0, 0, 42), IPMax: net.IPv4(10, 0, 0, 42), PortMin: 443, PortMax: 443,
		Protocol: "tcp", AppID: "l3", EnableTCPPrefL3: true,
	}
	stack := &capturingStack{}
	dialer := &Dialer{stack: stack, ipResources: []client.IPResource{resource}, resourceIndex: ipresource.New([]client.IPResource{resource})}

	if _, err := dialer.DialIPPort(context.Background(), "tcp", "10.0.0.42:443"); err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if !stack.ipResource.EnableTCPPrefL3 || stack.ipResource.AppID != "l3" {
		t.Fatalf("selected IP resource = %#v, want l3 TCP-prefers-L3", stack.ipResource)
	}
}

type capturingStack struct {
	domainResource client.DomainResource
	ipResource     client.IPResource
	udpCalls       int
}

func (s *capturingStack) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	if resource, ok := ctx.Value(resolve.ContextKeyDomainResource).(client.DomainResource); ok {
		s.domainResource = resource
	}
	if resource, ok := ctx.Value(resolve.ContextKeyIPResource).(client.IPResource); ok {
		s.ipResource = resource
	}
	return nil, nil
}
func (s *capturingStack) DialUDP(ctx context.Context, _ *net.UDPAddr) (net.Conn, error) {
	s.udpCalls++
	if resource, ok := ctx.Value(resolve.ContextKeyIPResource).(client.IPResource); ok {
		s.ipResource = resource
	}
	return nil, nil
}
