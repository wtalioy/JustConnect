package dial

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestInternalCampusDNSBypassesOnlyItsEndpointProtectionAndStillRequiresACL(t *testing.T) {
	r := resolve.NewResolver(nil, "203.0.113.53", "", 60, nil, nil, true)
	defer r.Close()
	p, err := policy.NewProtectionPolicy([]string{"203.0.113.0/24"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &capturingStack{}
	resource := client.IPResource{IPMin: net.ParseIP("203.0.113.53"), IPMax: net.ParseIP("203.0.113.53"), PortMin: 53, PortMax: 53, Protocol: "all"}
	d := NewDialer(s, r, []client.IPResource{resource}, false)
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return &p }
	ctx := context.WithValue(t.Context(), resolve.ContextKeyProtectionPolicy, &p)
	for _, network := range []string{"tcp", "udp"} {
		if _, err := d.DialCampusIPPort(ctx, network, "203.0.113.53:53"); !errors.Is(err, policy.ErrProtectedTarget) {
			t.Fatal("ordinary flow lost protection", err)
		}
		conn, err := d.DialCampusDNS(ctx, network, "203.0.113.53:53")
		if err != nil {
			t.Fatal(err)
		}
		if conn != nil {
			conn.Close()
		}
		for _, endpoint := range []string{"203.0.113.54:53", "203.0.113.53:54", "[::ffff:203.0.113.53]:53"} {
			if _, err := d.DialCampusDNS(ctx, network, endpoint); !errors.Is(err, ErrACLDenied) {
				t.Fatal("DNS exception escaped its fixed endpoint", endpoint, err)
			}
		}
	}
	if s.tcpCalls != 1 || s.udpCalls != 1 {
		t.Fatal("unexpected tunnel connection", s)
	}
	denied := NewDialer(s, r, nil, false)
	denied.ProtectionPolicy = d.ProtectionPolicy
	for _, network := range []string{"tcp", "udp", "icmp"} {
		if _, err := denied.DialCampusDNS(ctx, network, "203.0.113.53:53"); !errors.Is(err, ErrACLDenied) {
			t.Fatal("DNS bypassed resource ACL", err)
		}
	}
	if s.tcpCalls != 1 || s.udpCalls != 1 {
		t.Fatal("denied DNS reached the tunnel")
	}
}

func TestLiveProtectionOverridesCampusResourcesButNeverGrantsAuthorization(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, 16)
		n, peer, err := listener.ReadFrom(buffer)
		if err == nil {
			_, _ = listener.WriteTo(buffer[:n], peer)
		}
	}()
	current, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8", "::1/128"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &capturingStack{}
	ip := net.ParseIP("127.0.0.1")
	d := NewDialer(s, nil, []client.IPResource{{IPMin: ip, IPMax: ip, PortMin: 1, PortMax: 65535, Protocol: "all"}}, false)
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return &current }
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := d.DialIPPort(ctx, "udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	if n, err := conn.Read(buffer); err != nil || string(buffer[:n]) != "original" {
		t.Fatal("protected traffic did not retain original route", n, err)
	}
	if s.tcpCalls+s.udpCalls != 0 {
		t.Fatal("protected traffic entered campus")
	}
	d.alwaysUseVPN = true
	for _, network := range []string{"tcp", "udp"} {
		for _, host := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::1"} {
			if _, err := d.DialIPPort(ctx, network, net.JoinHostPort(host, "80")); !errors.Is(err, policy.ErrProtectedTarget) {
				t.Fatal(network, host, err)
			}
		}
		for _, host := range []string{"::ffff:127.0.0.1%1", "::1%1"} {
			if _, err := d.Dial(ctx, network, net.JoinHostPort(host, "80")); !errors.Is(err, policy.ErrProtectedTarget) {
				t.Fatal("scoped literal bypassed original-network protection", network, host, err)
			}
		}
	}
	current, _ = policy.NewProtectionPolicy([]string{"127.0.0.0/8"}, []string{"127.0.0.1"}, nil, nil)
	for _, network := range []string{"tcp", "udp"} {
		if _, err := d.DialIPPort(ctx, network, "127.0.0.1:80"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialIPPort(ctx, network, "[::ffff:127.0.0.1%1]:80"); err != nil {
			t.Fatal("authorized scoped IPv4 mapping rejected", network, err)
		}
		if _, err := d.Dial(ctx, network, "[::ffff:127.0.0.1%1]:80"); err != nil {
			t.Fatal("proxy scoped IPv4 mapping rejected", network, err)
		}
	}
	if s.tcpCalls != 3 || s.udpCalls != 3 {
		t.Fatal("explicit campus choice was not applied")
	}
	d.ipResources, d.resourceIndex = nil, nil
	d.resolver = resolve.NewResolver(nil, "", "", 1, nil, nil, false)
	defer d.resolver.Close()
	for _, forced := range []bool{false, true} {
		d.alwaysUseVPN = forced
		for _, network := range []string{"tcp", "udp"} {
			conn, err := d.DialIPPort(ctx, network, listener.LocalAddr().String())
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, ErrACLDenied) {
				t.Fatalf("campus choice bypassed authorization or fell back to original network (forced=%t network=%s): %v", forced, network, err)
			}
			scoped := net.JoinHostPort("::ffff:127.0.0.1%1", strconv.Itoa(listener.LocalAddr().(*net.UDPAddr).Port))
			conn, err = d.Dial(ctx, network, scoped)
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, ErrACLDenied) {
				t.Fatalf("mapped IPv4 zone escaped campus choice (forced=%t network=%s): %v", forced, network, err)
			}
		}
	}
	current, _ = policy.NewProtectionPolicy([]string{"127.0.0.0/8"}, nil, nil, nil)
	if _, err := d.DialIPPort(ctx, "tcp", "127.0.0.1:80"); !errors.Is(err, policy.ErrProtectedTarget) {
		t.Fatal("removed choice remained active", err)
	}
}

func TestCapturedDialNeverFallsBackOrChangesProxyRouting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	d := NewDialer(nil, nil, nil, false)
	if conn, err := d.DialCampusIPPort(ctx, "tcp", listener.Addr().String()); !errors.Is(err, ErrACLDenied) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("unauthorized capture fell back to reachable native target: %v", err)
	}
	protected, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protected }
	if _, err := d.DialCampusIPPort(ctx, "tcp", listener.Addr().String()); !errors.Is(err, policy.ErrProtectedTarget) {
		t.Fatalf("protected capture = %v", err)
	}
	conn, err := d.DialIPPort(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("captured dial changed ordinary proxy routing: %v", err)
	}
	conn.Close()
}

func TestIPPortEntryRejectsUnresolvedNames(t *testing.T) {
	dialer := NewDialer(nil, nil, nil, false)
	conn, err := dialer.DialIPPort(t.Context(), "udp", "localhost:9")
	if conn != nil {
		conn.Close()
	}
	if conn != nil || err == nil {
		t.Fatal("IP-only entry delegated unresolved destination to native name dialing", err)
	}
}

func TestDestinationPortCannotWrapIntoAnotherTunnelPort(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, test := range []struct {
			port  int
			valid bool
		}{{-1, false}, {0, false}, {1, true}, {65535, true}, {65536, false}, {70000, false}} {
			port := test.port
			stack := &capturingStack{}
			dialer := &Dialer{stack: stack, alwaysUseVPN: true}
			ctx := context.WithValue(t.Context(), resolve.ContextKeyDomainResource, client.DomainResource{Protocol: network, PortMin: port, PortMax: port})
			conn, err := dialer.DialIPPort(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if conn != nil {
				conn.Close()
			}
			if test.valid {
				if err != nil || stack.tcpCalls+stack.udpCalls != 1 {
					t.Fatalf("valid %s destination port %d was rejected: %v", network, port, err)
				}
			} else if err == nil || conn != nil || stack.tcpCalls != 0 || stack.udpCalls != 0 {
				t.Fatalf("invalid %s destination port %d reached tunnel: %v", network, port, err)
			}
		}
	}
}

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

func TestCampusDomainNeverFallsBackThroughOrdinaryProxyDialer(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	var public atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		public.Add(1)
		return nil, errors.New("unexpected original-network DNS")
	}}
	domains := client.DomainResources{"localhost": {{Protocol: "udp", PortMin: 9, PortMax: 9}}}
	for _, ip := range []net.IP{nil, net.IPv6loopback} {
		var records map[string][]net.IP
		if ip != nil {
			records = map[string][]net.IP{"localhost": {ip}}
		}
		resolver := resolve.NewResolver(nil, "", "", 1, domains, records, false)
		dialer := NewDialer(&capturingStack{}, resolver, nil, false)
		conn, err := dialer.Dial(t.Context(), "udp", "localhost:9")
		resolver.Close()
		if conn != nil {
			conn.Close()
		}
		if err == nil || conn != nil || public.Load() != 0 {
			t.Fatalf("campus domain escaped through ordinary dialer: IPv6=%t, queries=%d, connection=%t, error=%v", ip != nil, public.Load(), conn != nil, err)
		}
	}
}

func TestResolutionFailureCannotBypassDestinationPolicy(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	var bypass atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		bypass.Add(1)
		return nil, errors.New("unexpected second resolution outside destination policy")
	}}
	// An unusable configured DNS address deterministically fails before a query is sent.
	resolver := resolve.NewResolver(nil, "", "::invalid", 1, nil, nil, false)
	defer resolver.Close()
	current, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8"}, []string{"127.0.0.1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dialer := NewDialer(&capturingStack{}, resolver, nil, false)
	dialer.ProtectionPolicy = func() *policy.ProtectionPolicy { return &current }
	for _, network := range []string{"tcp", "udp"} {
		conn, err := dialer.Dial(t.Context(), network, "policy-bypass.invalid:9")
		if conn != nil {
			conn.Close()
		}
		if conn != nil || err == nil || bypass.Load() != 0 {
			t.Fatalf("resolution failure bypassed destination policy: network=%s queries=%d connection=%t error=%v", network, bypass.Load(), conn != nil, err)
		}
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
	tcpCalls       int
}

func (s *capturingStack) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	s.tcpCalls++
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
