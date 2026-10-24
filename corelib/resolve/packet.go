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
var ErrInvalidDNSResponse = errors.New("invalid campus DNS response")

const DNSPort = 53

// ExchangeCampus preserves DNS records; the caller supplies the ACL-enforcing campus dialer.
func (r *Resolver) ExchangeCampus(ctx context.Context, request *dns.Msg, transport string, dial client.DialContextFunc, publish func(context.Context, []netip.Addr) error) (*dns.Msg, error) {
	if request == nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 ||
		request.Question[0].Qclass != dns.ClassINET || (transport != "udp" && transport != "tcp") {
		return nil, ErrInvalidDNSQuestion
	}
	question := request.Question[0]
	host := normalizeHostname(question.Name)
	if host == "" || !dns.IsFqdn(question.Name) {
		return nil, ErrInvalidDNSQuestion
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
	explicit := false
	if r.ProtectionPolicy != nil {
		snapshot := r.ProtectionPolicy()
		ctx = context.WithValue(ctx, ContextKeyProtectionPolicy, snapshot)
		if snapshot != nil {
			allowed, protected := snapshot.CampusNameAllowed(host)
			if protected && !allowed {
				return nil, policy.ErrProtectedTarget
			}
			explicit = protected && allowed
		}
	}
	var prepare func([]netip.Addr) error
	if publish != nil {
		prepare = func(addresses []netip.Addr) error { return publish(ctx, addresses) }
	}
	ips, known := r.dnsResource[host]
	if _, _, granted := matchDomainResource(r.domainIndex, host); !granted && !known && !explicit {
		return nil, ErrOriginalDNSRequired
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
	exchange := func(network string) (*dns.Msg, error) {
		conn, err := dial(ctx, network, net.JoinHostPort(r.remoteDNSServer, strconv.Itoa(DNSPort)))
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
	if err == nil {
		_, err = r.bindCampusAnswer(request, reply, prepare)
	}
	return reply, err
}
