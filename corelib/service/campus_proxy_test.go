package service

import (
	"errors"
	"net"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestSOCKSResolutionUsesItsIngressBoundary(t *testing.T) {
	r := resolve.NewResolver(nil, "", "", 60, nil, map[string][]net.IP{"owned.campus.test": {net.ParseIP("203.0.113.7")}}, false)
	defer r.Close()
	d := dial.NewDialer(nil, r, nil, false)
	ordinary := sessionResolver{t.Context(), d}
	if _, ip, err := ordinary.Resolve(t.Context(), "localhost"); err != nil || !ip.IsLoopback() {
		t.Fatal("ordinary SOCKS lost native name resolution", ip, err)
	}
	strict := sessionResolver{t.Context(), d.CampusOnly()}
	if _, _, err := strict.Resolve(t.Context(), "localhost"); !errors.Is(err, resolve.ErrCampusDNSUnavailable) {
		t.Fatal("strict SOCKS used ordinary native DNS", err)
	}
	ctx, ip, err := strict.Resolve(t.Context(), "owned.campus.test")
	if err != nil || !ip.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatal("strict SOCKS lost the server's DNS record", ip, err)
	}
	if _, err := d.CampusOnly().DialIPPort(ctx, "tcp", "203.0.113.7:443"); !errors.Is(err, dial.ErrACLDenied) {
		t.Fatal("a DNS record became a resource authorization", err)
	}
	// A domain grant must survive SOCKS resolution for the common IP dialer.
	domains := client.DomainResources{"owned.campus.test": {{Protocol: "tcp", PortMin: 443, PortMax: 443}}}
	granted := resolve.NewResolver(nil, "", "", 60, domains, map[string][]net.IP{"owned.campus.test": {net.ParseIP("203.0.113.7")}}, false)
	defer granted.Close()
	resolver := sessionResolver{t.Context(), dial.NewDialer(nil, granted, nil, false).CampusOnly()}
	ctx, _, err = resolver.Resolve(t.Context(), "owned.campus.test")
	if resources, ok := ctx.Value(resolve.ContextKeyDomainResource).([]client.DomainResource); err != nil || !ok || len(resources) != 1 || resources[0].PortMin != 443 {
		t.Fatal("SOCKS resolution discarded the campus domain grant", err)
	}
}
