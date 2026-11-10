package resolve

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

const ContextKeyDomainDNS = contextKey("DOMAIN_DNS")

func ParseDomainDNSRules(text string) (map[string]string, error) {
	rules := make(map[string]string)
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		host := normalizeHostname(fields[0])
		name := policy.NameRule{Kind: "exact", Value: host}
		if len(fields) > 2 || !name.Matches(host) || !strings.Contains(host, ".") ||
			strings.Contains(host, "_") || strings.HasSuffix(host, ".localhost") || len(rules) >= maxDNSCacheEntries {
			return nil, ErrInvalidDNSQuestion
		}
		if _, duplicate := rules[host]; duplicate {
			return nil, ErrInvalidDNSQuestion
		}
		server := ""
		if len(fields) == 2 {
			address, err := netip.ParseAddr(fields[1])
			if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() {
				return nil, ErrCampusDNSUnavailable
			}
			server = address.String()
		}
		rules[host] = server
	}
	return rules, nil
}

func (r *Resolver) domainDNSEndpoint(server string) string {
	if server != "" {
		return net.JoinHostPort(server, strconv.Itoa(DNSPort))
	}
	if endpoint, valid := r.CampusDNSEndpoint(); valid {
		return endpoint.String()
	}
	return ""
}

func (r *Resolver) lookupDomainDNS(ctx context.Context, host, server string) (net.IP, error) {
	request := new(dns.Msg).SetQuestion(dns.Fqdn(host), dns.TypeA)
	reply, err := exchangeDNSPacket(ctx, request, "udp", server, r.DomainDNSDial)
	if err != nil {
		return nil, err
	}
	addresses, err := r.bindCampusAnswer(request, reply, nil)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, ErrCampusDNSUnavailable
	}
	ip := net.IP(addresses[0].AsSlice())
	r.setDNSCache(host, ip, true)
	return ip, nil
}
