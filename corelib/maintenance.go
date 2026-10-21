package corelib

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"github.com/wtalioy/JustConnect/corelib/stack"
)

func ValidateKeepAlive(mode, target string) error {
	if len(target) > 8192 || strings.ContainsAny(target, "\x00\r\n") {
		return errors.New("invalid_keepalive_target")
	}
	switch mode {
	case "", "auto", "off":
		return nil
	case "target":
		u, err := url.Parse(target)
		if err == nil && u.Hostname() != "" && u.User == nil && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" {
			if (u.Scheme == "https" && (u.Port() == "" || u.Port() == "443")) || (u.Scheme == "http" && (u.Port() == "" || u.Port() == "80")) {
				return nil
			}
		}
	}
	return errors.New("invalid_keepalive_options")
}

func authorizedDNS(address string, ips []client.IPResource) net.IP {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	if _, ok := ipresource.New(ips).Match(ip, "udp", 53); !ok {
		return nil
	}
	return ip
}

// trafficProbe uses only campus resources and never falls back to the original network.
func trafficProbe(ctx context.Context, mode, target, remoteDNS string, network stack.Stack, resolver *resolve.Resolver, ips []client.IPResource, tlsPolicy *tls.Config) string {
	if ips == nil {
		ips = []client.IPResource{}
	}
	if mode == "off" {
		return "disabled"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dnsIP := authorizedDNS(remoteDNS, ips)
	if mode != "target" {
		if dnsIP == nil {
			return "unavailable"
		}
		conn, err := network.DialUDP(ctx, &net.UDPAddr{IP: dnsIP, Port: 53})
		if err != nil {
			return "failed"
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		request := new(dns.Msg)
		request.SetQuestion(".", dns.TypeNS)
		reply, _, err := (&dns.Client{Timeout: 10 * time.Second}).ExchangeWithConnContext(ctx, request, &dns.Conn{Conn: conn})
		if err != nil || reply == nil || reply.Rcode != dns.RcodeSuccess {
			return "failed"
		}
		return "succeeded"
	}
	if ValidateKeepAlive(mode, target) != nil {
		return "unavailable"
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, protocol, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				ctx, ip, err = resolver.ResolveCampus(ctx, host, dnsIP != nil)
				if err != nil {
					return nil, err
				}
			}
			if ip.To4() == nil {
				return nil, dial.ErrACLDenied
			}
			return dial.NewDialer(network, resolver, ips, true, "").DialIPPort(ctx, protocol, net.JoinHostPort(ip.String(), port))
		},
	}
	if tlsPolicy != nil {
		transport.TLSClientConfig = tlsPolicy.Clone()
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "unavailable"
	}
	reply, err := httpClient.Do(request)
	if err != nil {
		if errors.Is(err, dial.ErrACLDenied) || errors.Is(err, resolve.ErrCampusDNSUnavailable) {
			return "unavailable"
		}
		return "failed"
	}
	defer reply.Body.Close()
	if reply.StatusCode < 200 || reply.StatusCode >= 300 {
		return "failed"
	}
	return "succeeded"
}
