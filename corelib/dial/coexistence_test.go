package dial

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestCampusIngressCannotReenterOrdinaryUpstream(t *testing.T) {
	campus := &capturingStack{}
	d := NewDialer(campus, nil, []client.IPResource{{IPMin: net.ParseIP("203.0.113.7"), IPMax: net.ParseIP("203.0.113.7"), PortMin: 443, PortMax: 443, Protocol: "tcp"}}, false)
	upstreamFailure := errors.New("owned ordinary upstream")
	calls := 0
	d.Upstream = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, upstreamFailure
	}
	strict := d.CampusOnly()
	for _, network := range []string{"tcp", "udp"} {
		for _, address := range []string{"203.0.113.8:443", "[2001:db8::8]:443", "203.0.113.7:80", "not-an-endpoint", "localhost:443"} {
			if _, err := strict.Dial(t.Context(), network, address); !errors.Is(err, ErrACLDenied) {
				t.Fatalf("campus ingress escaped its resource boundary: %s %s: %v", network, address, err)
			}
		}
	}
	if calls != 0 || campus.tcpCalls != 0 || campus.udpCalls != 0 {
		t.Fatal("denied ingress reached a downstream connection", calls, campus)
	}
	if _, err := strict.Dial(t.Context(), "tcp", "203.0.113.7:443"); err != nil || campus.tcpCalls != 1 {
		t.Fatal("authorized campus TCP did not reach its resource", err)
	}
	if _, err := strict.Dial(t.Context(), "udp", "203.0.113.7:443"); !errors.Is(err, ErrACLDenied) || campus.udpCalls != 0 {
		t.Fatal("TCP grant authorized UDP", err)
	}
	for _, address := range []string{"203.0.113.8:443", "[2001:db8::8]:443"} {
		for _, network := range []string{"tcp", "udp"} {
			if _, err := d.Dial(t.Context(), network, address); !errors.Is(err, upstreamFailure) {
				t.Fatal("ordinary upstream failure fell back to a different exit", err)
			}
		}
	}
	if calls != 4 || campus.tcpCalls != 1 || campus.udpCalls != 0 {
		t.Fatal("campus and ordinary exits were mixed", calls, campus)
	}
}

func TestOrdinaryUpstreamRetainsDomainForClashRules(t *testing.T) {
	r := resolve.NewResolver(nil, "", "", 60, nil, map[string][]net.IP{"ordinary.test": {net.ParseIP("203.0.113.9")}}, false)
	defer r.Close()
	d := NewDialer(nil, r, nil, false)
	wantErr := errors.New("owned upstream result")
	var target string
	d.Upstream = func(_ context.Context, _, address string) (net.Conn, error) {
		target = address
		return nil, wantErr
	}
	for _, network := range []string{"tcp", "udp"} {
		if _, err := d.Dial(t.Context(), network, "ordinary.test:443"); !errors.Is(err, wantErr) || target != "ordinary.test:443" {
			t.Fatal("ordinary domain was replaced with its IP before Clash rule matching", target, err)
		}
		ctx, ip, err := d.Resolve(t.Context(), "ordinary.test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialIPPort(ctx, network, net.JoinHostPort(ip.String(), "443")); !errors.Is(err, wantErr) || target != "ordinary.test:443" {
			t.Fatal("SOCKS resolution discarded the ordinary domain", target, err)
		}
	}
}

func TestProtectedTargetsBypassOrdinaryUpstream(t *testing.T) {
	protection, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8", "::1/128"}, nil, []policy.NameRule{{Kind: "exact", Value: "localhost"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(nil, nil, nil, false)
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return &protection }
	d.Upstream = func(context.Context, string, string) (net.Conn, error) {
		t.Error("protected target entered ordinary proxy")
		return nil, errors.New("unexpected proxy")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	for _, host := range []string{"127.0.0.1", "localhost"} {
		address := net.JoinHostPort(host, port)
		conn, err := d.Dial(t.Context(), "tcp", address)
		if err != nil {
			t.Fatal("native protected path failed", err)
		}
		conn.Close()
		if _, err := d.CampusOnly().Dial(t.Context(), "tcp", address); !errors.Is(err, policy.ErrProtectedTarget) && !errors.Is(err, ErrACLDenied) {
			t.Fatal("protected target was allowed into strict campus ingress", err)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		if _, err := d.CampusOnly().Dial(t.Context(), network, "[::1]:443"); !errors.Is(err, policy.ErrProtectedTarget) {
			t.Fatal("protected IPv6 entered campus or upstream", err)
		}
	}
}
