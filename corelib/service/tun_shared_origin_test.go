package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestTUNCampusSharesAuthenticationAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Error("relay lost the original TLS name", r.Host, r.TLS.ServerName)
		}
		io.WriteString(w, "campus-course")
	}))
	t.Cleanup(server.Close)
	shared := netip.MustParseAddr("192.0.2.7")
	campus := &ingressCampus{tcpAddress: server.Listener.Addr().String(), called: make(chan string, 16)}
	resources := client.DomainResources{
		"example.com": {{Protocol: "tcp", PortMin: 443, PortMax: 443, AppID: "course"}},
		"login.test":  {{Protocol: "tcp", PortMin: 443, PortMax: 443, AppID: "authentication"}},
	}
	r := resolve.NewResolver(campus, "", "", 60, resources, map[string][]net.IP{
		"example.com": {net.IP(shared.AsSlice())}, "login.test": {net.IP(shared.AsSlice())},
	}, false)
	t.Cleanup(r.Close)
	var protection atomic.Pointer[policy.ProtectionPolicy]
	r.ProtectionPolicy = protection.Load
	d := dial.NewDialer(campus, r, nil, false)
	d.ProtectionPolicy = protection.Load
	d.OriginalAuthentication = dial.AuthenticationOrigin{Name: "login.test", Address: shared}
	ordinary := errors.New("original network selected")
	d.Upstream = func() client.DialContextFunc {
		return func(context.Context, string, string) (net.Conn, error) { return nil, ordinary }
	}
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	device := &dnsPacketDevice{newPacketDevice()}
	if err := p.AttachTUN(device, 1400, nil); err != nil {
		t.Fatal(err)
	}
	peer := tunPeer(t, device.packetDevice)
	local, ownedPeer := device.TUNAddresses()
	flow := stack.TransportEndpointID{LocalAddress: tcpip.AddrFromSlice(ownedPeer.AsSlice()), RemoteAddress: tcpip.AddrFromSlice(local.AsSlice()), LocalPort: 443}
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("private peer forwarded without a live DNS binding")
	}
	query := func(host string) *dns.Msg {
		t.Helper()
		reply, err := p.tun.exchangeDNS(new(dns.Msg).SetQuestion(host+".", dns.TypeA), "udp")
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if got := query("login.test").Answer[0].(*dns.A).A.String(); got != shared.String() {
		t.Fatal("authentication address was aliased", got)
	}
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("authentication binding granted a campus alias")
	}
	if got := query("example.com").Answer[0].(*dns.A).A.String(); got != ownedPeer.String() {
		t.Fatal("shared campus name did not use the private peer", got)
	}
	if got := r.CampusDNSRecords()["example.com"]; len(got) != 1 || got[0] != shared.String() {
		t.Fatal("alias replaced the actual authorization binding", got)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, mode := range []string{"transparent", "named"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var conn net.Conn
			var err error
			if mode == "transparent" {
				conn, err = gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: flow.LocalAddress, Port: 443}, ipv4.ProtocolNumber)
			} else {
				conn, err = d.Dial(ctx, "tcp", "example.com:443")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			secure.SetDeadline(deadline)
			io.WriteString(secure, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(secure), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "campus-course" {
				t.Fatal("shared campus TLS relay failed", string(body), err)
			}
			if called := <-campus.called; called != "tcp:192.0.2.7:443" {
				t.Fatal("alias reached the wrong destination", called)
			}
		})
	}
	auth := context.WithValue(t.Context(), resolve.ContextKeyResolveHost, "login.test")
	auth = context.WithValue(auth, resolve.ContextKeyDomainResource, resources["login.test"])
	if _, err := d.DialIPPort(auth, "tcp", "192.0.2.7:443"); !errors.Is(err, ordinary) {
		t.Fatal("authentication left the original network", err)
	}
	flow.LocalPort = 444
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("alias expanded campus port authorization")
	}
	flow.LocalPort = 443
	flow.RemoteAddress = tcpip.AddrFrom4([4]byte{198, 18, 0, 9})
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("foreign source reached the private alias")
	}
	blocked, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "exact", Value: "example.com"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&blocked)
	flow.RemoteAddress = tcpip.AddrFromSlice(local.AsSlice())
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("withdrawn campus name retained its private alias")
	}
}
