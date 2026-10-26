package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

var ErrOriginalDNSRequired = errors.New("DNS question requires the original network")
var ErrInvalidDNSQuestion = errors.New("invalid DNS question")
var ErrInvalidDNSResponse = errors.New("invalid DNS response")
var ErrCampusIPv6Unsupported = errors.New("campus IPv6 ingress is unavailable")

const DNSPort = 53

// ExchangeCampus preserves DNS records; the caller supplies the ACL-enforcing campus dialer.
func (r *Resolver) ExchangeCampus(ctx context.Context, request *dns.Msg, transport string, dial client.DialContextFunc, publish func(context.Context, []netip.Addr) error) (*dns.Msg, error) {
	var prepare func(context.Context, []netip.Addr, bool) error
	if publish != nil {
		prepare = func(ctx context.Context, addresses []netip.Addr, _ bool) error { return publish(ctx, addresses) }
	}
	return r.exchangeDNS(ctx, request, transport, dial, prepare, true, "")
}

// ExchangeTUN keeps protected questions on their confirmed original DNS source.
func (r *Resolver) ExchangeTUN(ctx context.Context, request *dns.Msg, transport string, dial client.DialContextFunc,
	publish func(context.Context, []netip.Addr, bool) error) (*dns.Msg, error) {
	return r.exchangeDNS(ctx, request, transport, dial, publish, false, "")
}

// ExchangeNative preserves the resolver link selected by the operating system.
func (r *Resolver) ExchangeNative(ctx context.Context, request *dns.Msg, transport, source string, dial client.DialContextFunc,
	publish func(context.Context, []netip.Addr, bool) error) (*dns.Msg, error) {
	if source == "" {
		return nil, ErrOriginalDNSRequired
	}
	return r.exchangeDNS(ctx, request, transport, dial, publish, false, source)
}

func (r *Resolver) exchangeDNS(ctx context.Context, request *dns.Msg, transport string, dial client.DialContextFunc,
	publish func(context.Context, []netip.Addr, bool) error, campusOnly bool, source string) (*dns.Msg, error) {
	if request == nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 ||
		request.Question[0].Qclass != dns.ClassINET || (transport != "udp" && transport != "tcp") {
		return nil, ErrInvalidDNSQuestion
	}
	question := request.Question[0]
	host := normalizeHostname(question.Name)
	if (host == "" && (source == "" || question.Name != ".")) || !dns.IsFqdn(question.Name) {
		return nil, ErrInvalidDNSQuestion
	}
	// Reserved local names never belong to the captured upstream DNS path.
	if !campusOnly && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return nil, ErrOriginalDNSRequired
	}
	var selected *originalDNSRoute
	if source != "" {
		if r.OriginalDNS != nil {
			if index, found := r.OriginalDNS.listeners[source]; found {
				selected = &r.OriginalDNS.routes[index]
			}
		}
		if selected == nil {
			return nil, ErrOriginalDNSRequired
		}
	}
	r.resolutionMu.Lock()
	if r.resolutionClosed {
		r.resolutionMu.Unlock()
		return nil, net.ErrClosed
	}
	r.workers.Add(1)
	r.resolutionMu.Unlock()
	defer r.workers.Done()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if selected != nil && question.Name == "." {
		return r.exchangeOriginalRoute(ctx, request, transport, *selected, nil, false)
	}
	explicit := false
	if r.ProtectionPolicy != nil {
		snapshot := r.ProtectionPolicy()
		ctx = context.WithValue(ctx, ContextKeyProtectionPolicy, snapshot)
		if snapshot != nil {
			allowed, protected := snapshot.CampusNameAllowed(host)
			if protected && !allowed {
				if !campusOnly {
					if selected != nil {
						return r.exchangeOriginalRoute(ctx, request, transport, *selected, publish, true)
					}
					return r.exchangeOriginal(ctx, request, transport, publish)
				}
				return nil, policy.ErrProtectedTarget
			}
			explicit = protected && allowed
		}
	}
	var prepare func([]netip.Addr) error
	if publish != nil {
		prepare = func(addresses []netip.Addr) error { return publish(ctx, addresses, false) }
	}
	ips, known := r.dnsResource[host]
	if selected != nil && !r.useRemoteDNS && !known {
		return r.exchangeOriginalRoute(ctx, request, transport, *selected, nil, false)
	}
	if _, _, granted := matchDomainResource(r.domainIndex, host); !granted && !known && !explicit {
		if selected != nil {
			return r.exchangeOriginalRoute(ctx, request, transport, *selected, nil, false)
		}
		return nil, ErrOriginalDNSRequired
	}
	if !campusOnly && question.Qtype == dns.TypeAAAA {
		return nil, ErrCampusIPv6Unsupported
	}
	if known && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		reply := new(dns.Msg).SetReply(request)
		reply.RecursionAvailable = true
		for _, ip := range ips {
			header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: r.dnsTTL}
			if v4 := ip.To4(); question.Qtype == dns.TypeA && v4 != nil {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: append(net.IP(nil), v4...)})
			} else if question.Qtype == dns.TypeAAAA && v4 == nil && ip.To16() != nil {
				reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: append(net.IP(nil), ip.To16()...)})
			}
		}
		_, err := r.bindCampusAnswer(request, reply, prepare)
		return reply, err
	}
	if !r.useRemoteDNS || r.remoteDNSServer == "" || dial == nil {
		return nil, ErrCampusDNSUnavailable
	}
	reply, err := exchangeDNSPacket(ctx, request, transport, net.JoinHostPort(r.remoteDNSServer, strconv.Itoa(DNSPort)), dial)
	if err == nil {
		_, err = r.bindCampusAnswer(request, reply, prepare)
	}
	return reply, err
}

func exchangeDNSPacket(ctx context.Context, request *dns.Msg, transport, server string, dial client.DialContextFunc) (*dns.Msg, error) {
	question := request.Question[0]
	exchange := func(network string) (*dns.Msg, error) {
		conn, err := dial(ctx, network, server)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		interrupt := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer interrupt()
		wire := &dns.Client{Net: network}
		reply, _, err := wire.ExchangeWithConnContext(ctx, request, &dns.Conn{Conn: conn, UDPSize: dns.MaxMsgSize})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if !reply.Response || reply.Opcode != dns.OpcodeQuery || len(reply.Question) != 1 ||
			reply.Question[0].Qtype != question.Qtype || reply.Question[0].Qclass != question.Qclass ||
			!strings.EqualFold(reply.Question[0].Name, question.Name) {
			return nil, ErrInvalidDNSResponse
		}
		return reply, nil
	}
	reply, err := exchange(transport)
	if transport == "udp" && ctx.Err() == nil && (err != nil || reply.Truncated) {
		reply, err = exchange("tcp")
	}
	return reply, err
}
