package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (i *tunIngress) dnsFlow(id stack.TransportEndpointID) bool {
	return i.peer.IsValid() && id.LocalAddress.String() == i.peer.String() && id.LocalPort == resolve.DNSPort &&
		id.RemoteAddress.String() == i.local.String()
}

func (i *tunIngress) serveDNS(transport string, conn net.Conn) {
	stream := &dns.Conn{Conn: conn}
	buffer := make([]byte, maxUDPPacket)
	for {
		if err := conn.SetDeadline(time.Now().Add(tunUDPIdleTimeout)); err != nil {
			return
		}
		var request *dns.Msg
		if transport == "tcp" {
			var err error
			request, err = stream.ReadMsg()
			if err != nil {
				return
			}
		} else {
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			request = new(dns.Msg)
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
		}
		reply := new(dns.Msg).SetReply(request)
		if i.owner.resolver == nil {
			reply.Rcode = dns.RcodeServerFailure
		} else if len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeAAAA {
			// shortcut: refuse AAAA until the transparent ingress can carry campus IPv6.
			reply.Rcode = dns.RcodeNotImplemented
		} else {
			answer, err := i.owner.resolver.ExchangeCampus(i.owner.ctx, request, transport, i.owner.dialer.DialCampusIPPort,
				func(ctx context.Context, addresses []netip.Addr) error {
					return i.prepareDNSRoutes(ctx, request.Question[0].Name, addresses)
				})
			if err == nil {
				reply = answer
			} else if errors.Is(err, resolve.ErrInvalidDNSQuestion) {
				reply.Rcode = dns.RcodeFormatError
			} else if errors.Is(err, resolve.ErrOriginalDNSRequired) || errors.Is(err, policy.ErrProtectedTarget) {
				reply.Rcode = dns.RcodeRefused
			} else {
				reply.Rcode = dns.RcodeServerFailure
			}
		}
		if transport == "tcp" {
			if stream.WriteMsg(reply) != nil {
				return
			}
		} else {
			size := dns.MinMsgSize
			if option := request.IsEdns0(); option != nil {
				size = max(size, min(int(option.UDPSize()), maxUDPPacket))
			}
			reply.Truncate(size)
			data, err := reply.Pack()
			if err != nil {
				return
			}
			n, err := conn.Write(data)
			if err != nil || n != len(data) {
				return
			}
		}
	}
}

func (i *tunIngress) prepareDNSRoutes(ctx context.Context, host string, addresses []netip.Addr) error {
	if i.publishDNSRoutes == nil {
		return nil
	}
	var current *policy.ProtectionPolicy
	if i.owner.dialer.ProtectionPolicy != nil {
		current = i.owner.dialer.ProtectionPolicy()
	}
	if current != nil {
		if allowed, protected := current.CampusNameAllowed(host); protected && !allowed {
			return policy.ErrProtectedTarget
		}
	}
	for _, address := range addresses {
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address == i.local || address == i.peer {
			return policy.ErrProtectedTarget
		}
		if current != nil {
			if allowed, _ := current.CampusAllowed(address); !allowed {
				return policy.ErrProtectedTarget
			}
		}
	}
	return i.publishDNSRoutes(ctx, addresses)
}
