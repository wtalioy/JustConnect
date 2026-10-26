package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

func (p *Listeners) OriginalDNSListeners() map[string]string {
	result := make(map[string]string)
	if !p.closed.Load() {
		for name, address := range p.originalDNS {
			result[name] = address
		}
	}
	return result
}

func (p *Listeners) listenOriginalDNS() error {
	if p.resolver == nil {
		return nil
	}
	endpoints := p.resolver.OriginalDNS.ListenSources()
	if len(endpoints) == 0 {
		return nil
	}
	p.originalDNS = make(map[string]string)
	p.dnsReady = make(chan struct{})
	p.dnsWorkers = make(chan struct{}, maxTUNFlows)
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	available := make(map[string]bool)
	assigned := make(map[netip.Addr]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		available[iface.Name] = true
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				assigned[prefix.Addr().Unmap()] = true
			}
		}
	}
	for source, route := range endpoints {
		name, address := route.Interface, route.Listen
		endpoint, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !available[name] || !assigned[endpoint.Addr()] {
			return errors.New("original DNS requires an available query interface and assigned local listener address")
		}
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		p.listeners = append(p.listeners, listener)
		udpAddress, err := net.ResolveUDPAddr("udp4", listener.Addr().String())
		if err != nil {
			return err
		}
		udp, err := net.ListenUDP("udp4", udpAddress)
		if err != nil {
			return err
		}
		if _, err := p.own(udp); err != nil {
			return err
		}
		p.originalDNS[source] = listener.Addr().String()
		local := endpoint.Addr()
		p.start(func() { p.readOriginalDNS(udp, source, local) })
		p.start(func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					if p.ctx.Err() == nil {
						p.fail(err)
					}
					return
				}
				peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
				if !localDNSPeer(peer, local) {
					_ = conn.Close()
					continue
				}
				owned, err := p.own(conn)
				if err == nil && !p.startDNS(func() { defer owned.Close(); p.serveOriginalDNS(owned, source) }) {
					_ = owned.Close()
				}
			}
		})
	}
	return nil
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
