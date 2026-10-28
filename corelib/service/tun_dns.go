package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
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
	if transport == "tcp" {
		serveDNSTCP(conn, func(request *dns.Msg) (*dns.Msg, error) { return i.exchangeDNS(request, transport) })
		return
	}
	buffer := make([]byte, maxUDPPacket)
	for {
		if err := conn.SetDeadline(time.Now().Add(tunUDPIdleTimeout)); err != nil {
			return
		}
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		request := new(dns.Msg)
		if request.Unpack(buffer[:n]) != nil {
			continue
		}
		answer, err := i.exchangeDNS(request, transport)
		data, err := dnsDatagram(request, dnsResponse(request, answer, err))
		if err != nil {
			return
		}
		n, err = conn.Write(data)
		if err != nil || n != len(data) {
			return
		}
	}
}

func serveDNSTCP(conn net.Conn, exchange func(*dns.Msg) (*dns.Msg, error)) {
	stream := &dns.Conn{Conn: conn}
	for {
		if conn.SetDeadline(time.Now().Add(tunUDPIdleTimeout)) != nil {
			return
		}
		request, err := stream.ReadMsg()
		if err != nil {
			return
		}
		answer, err := exchange(request)
		if stream.WriteMsg(dnsResponse(request, answer, err)) != nil {
			return
		}
	}
}

func dnsResponse(request, answer *dns.Msg, err error) *dns.Msg {
	if err == nil && answer != nil {
		return answer
	}
	reply := new(dns.Msg).SetReply(request)
	switch {
	case errors.Is(err, resolve.ErrInvalidDNSQuestion):
		reply.Rcode = dns.RcodeFormatError
	case errors.Is(err, resolve.ErrCampusIPv6Unsupported):
		reply.Rcode = dns.RcodeNotImplemented
	case errors.Is(err, resolve.ErrOriginalDNSRequired), errors.Is(err, policy.ErrProtectedTarget):
		reply.Rcode = dns.RcodeRefused
	default:
		reply.Rcode = dns.RcodeServerFailure
	}
	return reply
}

func dnsDatagram(request, reply *dns.Msg) ([]byte, error) {
	size := dns.MinMsgSize
	if option := request.IsEdns0(); option != nil {
		size = max(size, min(int(option.UDPSize()), maxUDPPacket))
	}
	reply.Truncate(size)
	return reply.Pack()
}

func (i *tunIngress) exchangeDNS(request *dns.Msg, transport string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(i.owner.ctx, tunUDPIdleTimeout)
	defer cancel()
	return i.exchangeDNSOn(ctx, request, transport, "")
}

func (i *tunIngress) exchangeDNSOn(ctx context.Context, request *dns.Msg, transport, source string) (*dns.Msg, error) {
	if i.owner.resolver == nil {
		return nil, net.ErrClosed
	}
	var held []dnsPublication
	defer func() {
		if len(held) == 0 {
			return
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		for _, publication := range held {
			i.publishingDNS[publication]--
			if i.publishingDNS[publication] == 0 {
				delete(i.publishingDNS, publication)
			}
		}
	}()
	publish := func(ctx context.Context, addresses []netip.Addr, original bool) error {
		if original {
			var err error
			addresses, err = i.originalDNSRoutes(request.Question[0].Name, addresses)
			if err != nil {
				return err
			}
		} else if err := i.checkDNSRoutes(ctx, request.Question[0].Name, addresses); err != nil {
			return err
		}
		if len(addresses) == 0 {
			return nil
		}
		if i.publishDNSRoutes == nil {
			if original {
				return policy.ErrProtectedTarget
			}
			return nil
		}
		i.mu.Lock()
		if i.closed {
			i.mu.Unlock()
			return net.ErrClosed
		}
		if i.publishingDNS == nil {
			i.publishingDNS = make(map[dnsPublication]int)
		}
		name := ""
		if original {
			name = strings.TrimSuffix(strings.ToLower(request.Question[0].Name), ".")
		}
		for _, address := range addresses {
			publication := dnsPublication{address: address, originalName: name}
			i.publishingDNS[publication]++
			held = append(held, publication)
		}
		i.mu.Unlock()
		return i.publishDNSRoutes(ctx, addresses, original)
	}
	if source != "" {
		return i.owner.resolver.ExchangeNative(ctx, request, transport, source, i.owner.dialer.DialCampusDNS, publish)
	}
	return i.owner.resolver.ExchangeTUN(ctx, request, transport, i.owner.dialer.DialCampusDNS, publish)
}

func (i *tunIngress) checkDNSRoutes(ctx context.Context, host string, addresses []netip.Addr) error {
	var current *policy.ProtectionPolicy
	if i.owner.dialer.ProtectionPolicy != nil {
		current = i.owner.dialer.ProtectionPolicy()
	}
	if current != nil {
		if allowed, protected := current.CampusNameAllowed(host); protected && !allowed {
			return policy.ErrProtectedTarget
		}
	}
	ctx = context.WithValue(ctx, resolve.ContextKeyProtectionPolicy, current)
	for _, address := range addresses {
		original, err := i.owner.resolver.OriginalDNSProtectedIP(ctx, address)
		if err != nil {
			return err
		}
		if original {
			return policy.ErrProtectedTarget
		}
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address == i.local || address == i.peer {
			return policy.ErrProtectedTarget
		}
		if current != nil {
			if allowed, _ := current.CampusAllowed(address); !allowed {
				return policy.ErrProtectedTarget
			}
		}
	}
	return nil
}

func (i *tunIngress) originalDNSRoutes(host string, addresses []netip.Addr) ([]netip.Addr, error) {
	var current *policy.ProtectionPolicy
	if i.owner.dialer.ProtectionPolicy != nil {
		current = i.owner.dialer.ProtectionPolicy()
	}
	if current == nil {
		return nil, policy.ErrProtectedTarget
	}
	if allowed, protected := current.CampusNameAllowed(host); !protected || allowed {
		return nil, policy.ErrProtectedTarget
	}
	kept := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address == i.local || address == i.peer {
			return nil, policy.ErrProtectedTarget
		}
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() {
			continue
		}
		if allowed, _ := current.CampusAllowed(address); allowed {
			kept = append(kept, address)
		}
	}
	return kept, nil
}
