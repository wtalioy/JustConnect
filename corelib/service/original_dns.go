package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

var ErrOriginalDNSSealed = errors.New("original DNS sources are already prepared or the device is attached")

type originalDNSListener struct {
	source string
	local  netip.Addr
	tcp    net.Listener
	udp    *net.UDPConn
}

func (p *Listeners) OriginalDNSListeners() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[string]string)
	if !p.closed.Load() {
		for name, address := range p.originalDNS {
			result[name] = address
		}
	}
	return result
}

// PrepareOriginalDNS installs one immutable source set before device attachment.
func (p *Listeners) PrepareOriginalDNS(original *resolve.OriginalDNS) error {
	return p.prepareOriginalDNS(original, false)
}

func (p *Listeners) prepareOriginalDNS(original *resolve.OriginalDNS, startup bool) error {
	p.mu.Lock()
	if p.closed.Load() || p.ctx.Err() != nil {
		p.mu.Unlock()
		return net.ErrClosed
	}
	if p.resolver == nil || original == nil {
		p.mu.Unlock()
		return errors.New("original DNS requires a resolver and compiled sources")
	}
	if p.tun != nil || (!startup && p.resolver.OriginalDNS != nil) || (startup && p.resolver.OriginalDNS != original) {
		p.mu.Unlock()
		return ErrOriginalDNSSealed
	}
	opened, err := p.openOriginalDNS(original.ListenSources())
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.resolver.OriginalDNS = original
	if len(opened) != 0 {
		p.originalDNS = make(map[string]string, len(opened))
		p.dnsReady = make(chan struct{})
		p.dnsWorkers = make(chan struct{}, maxTUNFlows)
	}
	for _, entry := range opened {
		p.listeners = append(p.listeners, entry.tcp)
		p.connections[entry.udp] = struct{}{}
		p.originalDNS[entry.source] = entry.tcp.Addr().String()
	}
	p.mu.Unlock()
	for _, entry := range opened {
		p.start(func() { p.readOriginalDNS(entry.udp, entry.source, entry.local) })
		p.start(func() {
			for {
				conn, err := entry.tcp.Accept()
				if err != nil {
					if p.ctx.Err() == nil {
						p.fail(err)
					}
					return
				}
				peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
				if !localDNSPeer(peer, entry.local) {
					_ = conn.Close()
					continue
				}
				owned, err := p.own(conn)
				if err == nil && !p.startDNS(func() { defer owned.Close(); p.serveOriginalDNS(owned, entry.source) }) {
					_ = owned.Close()
				}
			}
		})
	}
	return nil
}

func (p *Listeners) openOriginalDNS(endpoints map[string]resolve.OriginalDNSListener) ([]originalDNSListener, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}
	var opened []originalDNSListener
	success := false
	defer func() {
		if !success {
			for _, entry := range opened {
				_ = entry.tcp.Close()
				_ = entry.udp.Close()
			}
		}
	}()
	interfaces, err := networkstate.Interfaces()
	if err != nil {
		return nil, err
	}
	available := make(map[string]bool)
	assigned := make(map[netip.Addr]bool)
	for _, iface := range interfaces {
		if !iface.Up {
			continue
		}
		available[iface.Name] = true
		for _, address := range iface.Addresses {
			if prefix, err := netip.ParsePrefix(address); err == nil {
				assigned[prefix.Addr().Unmap()] = true
			}
		}
	}
	for source, route := range endpoints {
		name, address := route.Interface, route.Listen
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		if (name != "" && !available[name]) || !assigned[endpoint.Addr()] {
			return nil, errors.New("original DNS requires an available query interface and assigned local listener address")
		}
		listener, udp, err := dnslistener.Listen(p.ctx, address)
		if err != nil {
			return nil, err
		}
		opened = append(opened, originalDNSListener{source: source, local: endpoint.Addr(), tcp: listener, udp: udp})
	}
	success = true
	return opened, nil
}

// A listener on an interface address must not become a LAN DNS server.
func localDNSPeer(peer, local netip.Addr) bool { return peer.IsLoopback() || peer == local }

func (p *Listeners) startDNS(work func()) bool {
	select {
	case p.dnsWorkers <- struct{}{}:
	default:
		return false
	}
	if !p.begin() {
		<-p.dnsWorkers
		return false
	}
	go func() {
		defer p.workers.Done()
		defer p.recoverWorker()
		defer func() { <-p.dnsWorkers }()
		work()
	}()
	return true
}

func (p *Listeners) readOriginalDNS(socket *net.UDPConn, source string, local netip.Addr) {
	buffer := make([]byte, maxUDPPacket)
	for {
		n, peer, err := socket.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if p.ctx.Err() == nil {
				p.fail(err)
			}
			return
		}
		if !localDNSPeer(peer.Addr().Unmap(), local) {
			continue
		}
		packet := bytes.Clone(buffer[:n])
		p.startDNS(func() {
			request := new(dns.Msg)
			if request.Unpack(packet) != nil {
				return
			}
			answer, err := p.exchangeOriginalDNS(request, "udp", source)
			data, err := dnsDatagram(request, dnsResponse(request, answer, err))
			if err == nil {
				_, _ = socket.WriteToUDPAddrPort(data, peer)
			}
		})
	}
}

func (p *Listeners) serveOriginalDNS(conn net.Conn, source string) {
	serveDNSTCP(conn, func(request *dns.Msg) (*dns.Msg, error) { return p.exchangeOriginalDNS(request, "tcp", source) })
}

func (p *Listeners) exchangeOriginalDNS(request *dns.Msg, transport, source string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(p.ctx, tunUDPIdleTimeout)
	defer cancel()
	select {
	case <-p.dnsReady:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p.mu.Lock()
	ingress := p.tun
	p.mu.Unlock()
	return ingress.exchangeDNSOn(ctx, request, transport, source)
}
