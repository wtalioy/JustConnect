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
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

const TrafficProbeTimeout = 10 * time.Second

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

func authorizedDNS(address string, dialer *dial.Dialer) net.IP {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	if !dialer.HasIPGrant(ip, "udp", 53) {
		return nil
	}
	return ip
}

// trafficProbe uses only campus resources and never falls back to the original network.
func trafficProbe(ctx context.Context, mode, target string, dnsIP net.IP, campus *dial.Dialer, resolver *resolve.Resolver, tlsPolicy *tls.Config) string {
	if mode == "off" {
		return "disabled"
	}
	ctx, cancel := context.WithTimeout(ctx, TrafficProbeTimeout)
	defer cancel()
	if mode != "target" {
		if dnsIP == nil {
			return "unavailable"
		}
		conn, err := campus.DialIPPort(ctx, "udp", net.JoinHostPort(dnsIP.String(), "53"))
		if err != nil {
			if errors.Is(err, policy.ErrProtectedTarget) {
				return "unavailable"
			}
			return "failed"
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		request := new(dns.Msg)
		request.SetQuestion(".", dns.TypeNS)
		reply, _, err := (&dns.Client{Timeout: TrafficProbeTimeout}).ExchangeWithConnContext(ctx, request, &dns.Conn{Conn: conn})
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
			return campus.DialIPPort(ctx, protocol, net.JoinHostPort(ip.String(), port))
		},
	}
	if tlsPolicy != nil {
		transport.TLSClientConfig = tlsPolicy.Clone()
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: TrafficProbeTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "unavailable"
	}
	reply, err := httpClient.Do(request)
	if err != nil {
		if errors.Is(err, policy.ErrProtectedTarget) || errors.Is(err, dial.ErrACLDenied) || errors.Is(err, resolve.ErrCampusDNSUnavailable) {
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
