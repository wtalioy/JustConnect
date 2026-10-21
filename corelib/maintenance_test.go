package corelib

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

type probeStack struct {
	calls atomic.Int32
	serve func(net.Conn)
}

func (s *probeStack) connection(packet bool) (net.Conn, error) {
	s.calls.Add(1)
	c, server := net.Pipe()
	if packet {
		c, server = packetProbeConn{c}, packetProbeConn{server}
	}
	go func() { defer server.Close(); s.serve(server) }()
	return c, nil
}
func (s *probeStack) DialTCP(context.Context, *net.TCPAddr) (net.Conn, error) {
	return s.connection(false)
}
func (s *probeStack) DialUDP(context.Context, *net.UDPAddr) (net.Conn, error) {
	return s.connection(true)
}

type packetProbeConn struct{ net.Conn }

func (c packetProbeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, &net.UDPAddr{}, err
}
func (c packetProbeConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func TestKeepAliveRejectsUnsafeTargetsAndNeverEscapesResources(t *testing.T) {
	for _, target := range []string{"", "ssh://campus.test/", "http://campus.test:22/", "https://u:p@campus.test/", "https://campus.test/?ticket=private", "https://campus.test/#private", "http://campus.test:443/"} {
		if ValidateKeepAlive("target", target) == nil {
			t.Fatalf("unsafe target accepted: %s", target)
		}
	}
	s := &probeStack{serve: func(net.Conn) { t.Error("probe escaped campus authorization") }}
	for _, mode := range []string{"off", "auto", "target"} {
		got := trafficProbe(t.Context(), mode, "http://192.0.2.10/", "192.0.2.53", s, nil, nil, nil)
		if got != "disabled" && got != "unavailable" {
			t.Fatal(mode, got)
		}
	}
	if s.calls.Load() != 0 {
		t.Fatal("probe sent unauthorized traffic")
	}
}
func TestTrafficProbeDistinguishesDNSFromHTTPAndRefusesRedirects(t *testing.T) {
	ip := net.ParseIP("192.0.2.10")
	ips := []client.IPResource{{IPMin: ip, IPMax: ip, PortMin: 1, PortMax: 65535, Protocol: "all"}}
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeRefused} {
		s := &probeStack{serve: func(conn net.Conn) {
			server := &dns.Conn{Conn: conn}
			request, err := server.ReadMsg()
			if err != nil {
				return
			}
			if len(request.Question) != 1 || request.Question[0].Name != "." || request.Question[0].Qtype != dns.TypeNS {
				t.Error("probe must not query an unrelated domain")
			}
			reply := new(dns.Msg)
			reply.SetReply(request)
			reply.Rcode = rcode
			_ = server.WriteMsg(reply)
		}}
		got := trafficProbe(t.Context(), "auto", "", ip.String(), s, nil, ips, nil)
		if (got == "succeeded") != (rcode == dns.RcodeSuccess) || s.calls.Load() != 1 {
			t.Fatal(got, rcode, s.calls.Load())
		}
	}
	for _, status := range []int{200, 302, 503} {
		s := &probeStack{serve: func(conn net.Conn) {
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			if request.Method != "GET" || request.URL.Path != "/repeatable" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
				t.Error("unexpected application probe")
			}
			response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Location": []string{"http://outside.test/"}}, Body: http.NoBody, ContentLength: 0, Close: true}
			_ = response.Write(conn)
		}}
		resolver := resolve.NewResolver(s, "", "", 60, nil, map[string][]net.IP{"campus.test": {ip}}, false)
		got := trafficProbe(t.Context(), "target", "http://campus.test/repeatable", "", s, resolver, ips, nil)
		resolver.Close()
		if (got == "succeeded") != (status == 200) || s.calls.Load() != 1 {
			t.Fatal(got, status, s.calls.Load())
		}
	}
}
func TestTrafficProbeCancellationClosesOwnedSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	closed := make(chan struct{})
	s := &probeStack{serve: func(conn net.Conn) { defer close(closed); cancel(); _, _ = io.Copy(io.Discard, conn) }}
	ip := net.ParseIP("192.0.2.53")
	got := trafficProbe(ctx, "auto", "", ip.String(), s, nil, []client.IPResource{{IPMin: ip, IPMax: ip, PortMin: 53, PortMax: 53, Protocol: "udp"}}, nil)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled probe left its socket open")
	}
	if got != "failed" || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal(got)
	}
}

func TestHTTPSProbeRequiresTrustAndUsesTheCampusStack(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	ip := net.ParseIP("127.0.0.1")
	ips := []client.IPResource{{IPMin: ip, IPMax: ip, PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	for _, trusted := range []bool{false, true} {
		s := &probeStack{serve: func(conn net.Conn) {
			server := tls.Server(conn, &tls.Config{Certificates: fixture.TLS.Certificates})
			defer server.Close()
			if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}}
		var policy *tls.Config
		if trusted {
			policy = &tls.Config{RootCAs: roots}
		}
		got := trafficProbe(t.Context(), "target", "https://127.0.0.1/repeatable", "", s, nil, ips, policy)
		if (got == "succeeded") != trusted || s.calls.Load() != 1 {
			t.Fatal("HTTPS trust or campus routing bypassed", trusted, got, s.calls.Load())
		}
	}
}
