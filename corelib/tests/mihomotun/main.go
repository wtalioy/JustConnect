//go:build darwin || windows

// This disposable-runner client never installs devices or changes system networking.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	vpnclient "github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

type facts struct {
	Upstream, FakeDNS, Address, Source, Interface string
}

func remoteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("requires an HTTPS test URL without credentials or fragment")
	}
	return u, nil
}

func directTLS(ctx context.Context, host, address string) (net.Conn, error) {
	return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp4", address)
}

func prepare(ctx context.Context, u *url.URL) (facts, func(), error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", u.Hostname())
	if err != nil || len(addresses) == 0 || !addresses[0].IsGlobalUnicast() || addresses[0].IsPrivate() || addresses[0].IsLoopback() {
		return facts{}, nil, fmt.Errorf("public test peer resolution: %v", err)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	f := facts{Address: net.JoinHostPort(addresses[0].String(), port)}
	connection, err := directTLS(ctx, u.Hostname(), f.Address)
	if err != nil {
		return facts{}, nil, fmt.Errorf("original TLS baseline: %w", err)
	}
	f.Source, _, _ = net.SplitHostPort(connection.LocalAddr().String())
	connection.Close()
	f.Interface, err = routeInterface(ctx, addresses[0])
	if err != nil {
		return facts{}, nil, err
	}
	tcp, udp, err := dnslistener.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		return facts{}, nil, err
	}
	f.Upstream = tcp.Addr().String()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg).SetReply(request)
		for _, q := range request.Question {
			if strings.EqualFold(q.Name, dns.Fqdn(u.Hostname())) && q.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 37}, A: addresses[0].AsSlice()})
			}
		}
		w.WriteMsg(reply)
	})
	servers := []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}}
	for _, server := range servers {
		go server.ActivateAndServe()
	}
	close := func() {
		for _, server := range servers {
			server.Shutdown()
		}
	}
	fakeTCP, fakeUDP, err := dnslistener.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		close()
		return facts{}, nil, err
	}
	f.FakeDNS = fakeTCP.Addr().String()
	fakeTCP.Close()
	fakeUDP.Close()
	return f, close, nil
}

func checkControl(ctx context.Context, u *url.URL, f facts, fakeRange string, original *underlay.Dialer) error {
	controller, err := mihomo.Discover(ctx)
	if err != nil || controller == nil {
		return fmt.Errorf("live controller discovery: %v", err)
	}
	defer controller.Close()
	if !controller.TunEnabled || controller.TunDevice == "" {
		return fmt.Errorf("official controller did not report an active TUN")
	}
	ip, _, _ := net.SplitHostPort(f.Address)
	deadline := time.Now().Add(5 * time.Second)
	for {
		iface, err := routeInterface(ctx, netip.MustParseAddr(ip))
		if err == nil && mihomo.SameInterface(iface, controller.TunDevice) {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("unbound peer route did not enter the reported TUN: %s %v", iface, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	question := new(dns.Msg).SetQuestion(dns.Fqdn(u.Hostname()), dns.TypeA)
	answer, _, err := (&dns.Client{Timeout: time.Second}).ExchangeContext(ctx, question, f.FakeDNS)
	if err != nil || len(answer.Answer) != 1 {
		return fmt.Errorf("official Fake-IP DNS: %v", err)
	}
	prefix, err := netip.ParsePrefix(fakeRange)
	address, ok := answer.Answer[0].(*dns.A)
	if err != nil || !ok || !prefix.Contains(netip.MustParseAddr(address.A.String())) {
		return fmt.Errorf("same control hostname did not receive its configured Fake-IP")
	}
	if connection, err := directTLS(ctx, u.Hostname(), f.Address); err == nil {
		connection.Close()
		return fmt.Errorf("unbound TLS bypassed the live rejecting TUN")
	}
	var systemQueries atomic.Int32
	originalResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		systemQueries.Add(1)
		return nil, fmt.Errorf("system DNS cannot supply the control address")
	}}
	defer func() { net.DefaultResolver = originalResolver }()
	device, err := net.InterfaceByName(controller.TunDevice)
	if err != nil {
		return err
	}
	addresses, err := device.Addrs()
	if err != nil {
		return err
	}
	var virtual net.IP
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil {
			virtual = ip
			break
		}
	}
	if virtual == nil {
		return fmt.Errorf("active TUN omitted its assigned IPv4 address")
	}
	controllerDialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		return err
	}
	defer controllerDialer.Close()
	original.ExcludeIP(virtual)
	for _, dialer := range []*underlay.Dialer{controllerDialer, original} {
		if err := checkOriginalHTTPS(ctx, u, f, dialer); err != nil {
			return err
		}
	}
	if systemQueries.Load() != 0 {
		return fmt.Errorf("control used system DNS")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "controlled", "tun": controller.TunDevice,
		"interface": f.Interface, "source": f.Source, "stages": 4, "modes": 2})
}

func checkOriginalHTTPS(ctx context.Context, u *url.URL, f facts, dialer *underlay.Dialer) error {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		connection, err := dialer.DialContext(ctx, "tcp4", address)
		if err == nil {
			source, _, _ := net.SplitHostPort(connection.LocalAddr().String())
			if source != f.Source || connection.RemoteAddr().String() != f.Address {
				connection.Close()
				return nil, fmt.Errorf("control left the original source or real peer address")
			}
		}
		return connection, err
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, stage := range []string{"auth-methods", "login", "gateway", "reconnect"} {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		request.Header.Set("X-JustConnect-Test-Stage", stage)
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("original TLS at %s: %w", stage, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil || response.StatusCode != http.StatusOK || len(body) == 0 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			return fmt.Errorf("verified original HTTPS response at %s: status=%d err=%v", stage, response.StatusCode, readErr)
		}
	}
	if dialer.InterfaceName() != f.Interface {
		return fmt.Errorf("control changed the original interface")
	}
	return nil
}

func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || len(os.Args) != 2 {
		return fmt.Errorf("requires a disposable runner and an explicit public HTTPS test URL")
	}
	if err := ensureOrdinary(); err != nil {
		return err
	}
	u, err := remoteURL(os.Args[1])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f, close, err := prepare(ctx, u)
	if err != nil {
		return err
	}
	defer close()
	original, err := underlay.New(underlay.Options{AutoDetect: false, LocalDNSServer: f.Upstream})
	if err != nil {
		return err
	}
	defer original.Close()
	_, port, _ := net.SplitHostPort(f.Address)
	baseline, err := vpnclient.DialTLSContext(ctx, original.DialContext, "tcp4", net.JoinHostPort(u.Hostname(), port),
		&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("pre-VPN original underlay TLS: %w", err)
	}
	baseline.Close()
	if err := json.NewEncoder(os.Stdout).Encode(f); err != nil {
		return err
	}
	input := json.NewDecoder(bufio.NewReader(os.Stdin))
	var command struct{ Phase, FakeRange string }
	if err := input.Decode(&command); err != nil || command.Phase != "test" {
		return fmt.Errorf("owned TUN startup barrier: %v", err)
	}
	if err := checkControl(ctx, u, f, command.FakeRange, original); err != nil {
		return err
	}
	if err := input.Decode(&command); err != nil || command.Phase != "restored" {
		return fmt.Errorf("owned TUN restoration barrier: %v", err)
	}
	ip, _, _ := net.SplitHostPort(f.Address)
	iface, err := routeInterface(ctx, netip.MustParseAddr(ip))
	if err != nil || iface != f.Interface {
		return fmt.Errorf("original route not restored: %s %v", iface, err)
	}
	connection, err := directTLS(ctx, u.Hostname(), f.Address)
	if err != nil {
		return fmt.Errorf("restored unbound TLS: %w", err)
	}
	connection.Close()
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": "restored", "interface": iface})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
