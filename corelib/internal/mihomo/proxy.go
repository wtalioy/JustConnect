package mihomo

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/things-go/go-socks5/statute"
	socketdialer "github.com/wtalioy/JustConnect/corelib/internal/dialer"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"github.com/wtalioy/JustConnect/corelib/internal/socksudp"
)

// Mihomo's standard UDP listener uses this fixed buffer (common/pool/buffer_standard.go).
// Reject larger requests rather than let the upstream silently truncate them.
const maxProxyUDPPacket = 16 * 1024

// Proxy uses only a live SOCKS/mixed listener advertised by the identified controller.
type Proxy struct {
	process model.Process
	address netip.AddrPort
	proof   *ListenerProof
}

type ProxyInfo struct {
	RuntimeState
	Endpoints       []string
	Proxy           *Proxy
	ListenerRequest *ListenerRequest
}

func (c *Client) Proxy(ctx context.Context) (*Proxy, error) {
	info, err := c.ObserveProxy(ctx)
	if err != nil {
		return nil, err
	}
	if info.Proxy == nil {
		return nil, ErrUnavailable
	}
	return info.Proxy, nil
}

// ObserveProxy reads runtime state once and verifies each advertised local listener.
func (c *Client) ObserveProxy(ctx context.Context, proofs ...ListenerProof) (ProxyInfo, error) {
	state, err := c.ReadState(ctx)
	if err != nil {
		return ProxyInfo{}, err
	}
	info := ProxyInfo{RuntimeState: state, Endpoints: []string{}}
	ports := []uint16{state.SOCKSPort, state.MixedPort, state.HTTPPort}
	for i, port := range ports {
		if port == 0 || i > 0 && port == ports[0] || i > 1 && port == ports[1] {
			continue
		}
		for _, host := range []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()} {
			address := netip.AddrPortFrom(host, port)
			var proof *ListenerProof
			for _, candidate := range proofs {
				if validListenerProof(ctx, c.endpoint.process, address, &candidate) {
					proof = &candidate
					break
				}
			}
			owned := proof != nil
			if !owned {
				proof, owned = localListenerProof(ctx, c.endpoint.process, address)
			}
			if owned {
				info.Endpoints = append(info.Endpoints, address.String())
				if info.Proxy == nil && (port == state.SOCKSPort || port == state.MixedPort) {
					info.Proxy = &Proxy{process: c.endpoint.process, address: address, proof: proof}
				}
			} else if needsListenerProof(ctx, c.endpoint.process, address) {
				if info.ListenerRequest == nil {
					info.ListenerRequest = &ListenerRequest{PID: c.endpoint.process.PID, Started: c.endpoint.process.Started}
				}
				info.ListenerRequest.Endpoints = append(info.ListenerRequest.Endpoints, address.String())
			}
		}
	}
	if ctx.Err() != nil {
		return ProxyInfo{}, ctx.Err()
	}
	return info, nil
}

func dialOwnedTCP(ctx context.Context, process model.Process, address netip.AddrPort, proof *ListenerProof) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owned := func() bool { return validListenerProof(ctx, process, address, proof) || ownsTCP(ctx, process, address) }
	if !address.Addr().IsLoopback() || !owned() {
		return nil, ErrUnavailable
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	if !owned() {
		conn.Close()
		return nil, ErrUnavailable
	}
	return conn, nil
}

func (p *Proxy) DialContext(parent context.Context, network, address string) (result net.Conn, resultErr error) {
	if network != "tcp" && network != "udp" {
		return nil, ErrUnavailable
	}
	target, err := statute.ParseAddrSpec(address)
	if err != nil || target.Port < 1 || target.Port > 65535 {
		return nil, ErrUnavailable
	}
	if target.AddrType == statute.ATYPDomain {
		if _, valid := dns.IsDomainName(target.FQDN); !valid || len(target.FQDN) > 255 {
			return nil, ErrUnavailable
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	control, err := dialOwnedTCP(ctx, p.process, p.address, p.proof)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			control.Close()
			if ctx.Err() != nil {
				resultErr = ctx.Err()
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	if _, err = control.Write([]byte{statute.VersionSocks5, 1, statute.MethodNoAuth}); err != nil {
		return nil, ErrUnavailable
	}
	method, err := statute.ParseMethodReply(control)
	if err != nil || method.Ver != statute.VersionSocks5 || method.Method != statute.MethodNoAuth {
		return nil, ErrUnavailable
	}
	request := statute.Request{Version: statute.VersionSocks5, Command: statute.CommandConnect, DstAddr: target}
	if network == "udp" {
		request.Command = statute.CommandAssociate
		request.DstAddr = statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.IPv4zero}
	}
	if _, err = control.Write(request.Bytes()); err != nil {
		return nil, ErrUnavailable
	}
	reply, err := statute.ParseReply(control)
	if err != nil || reply.Response != statute.RepSuccess || reply.Reserved != 0 {
		return nil, ErrUnavailable
	}
	if network == "tcp" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		success = true
		return control, nil
	}
	// RFC 1928 permits an unspecified relay address; it denotes this same proxy host.
	ip, valid := netip.AddrFromSlice(reply.BndAddr.IP)
	if !valid || reply.BndAddr.Port == 0 {
		return nil, ErrUnavailable
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		ip = p.address.Addr()
	}
	if !ip.IsLoopback() {
		return nil, ErrUnavailable
	}
	relay, err := (&net.Dialer{}).DialContext(ctx, "udp", netip.AddrPortFrom(ip, uint16(reply.BndAddr.Port)).String())
	if err != nil {
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		relay.Close()
		return nil, ctx.Err()
	}
	limit, err := socketdialer.SendBufferSize(relay.(*net.UDPConn))
	if err != nil || limit <= 0 {
		relay.Close()
		return nil, ErrUnavailable
	}
	// Native datagram capacity can be smaller than the upstream's buffer (notably macOS).
	conn := &proxyUDP{Conn: relay, control: control, target: target, limit: min(limit, maxProxyUDPPacket), header: (&statute.Datagram{DstAddr: target}).Header(), done: make(chan struct{})}
	go func() {
		defer close(conn.done)
		var b [1]byte
		_, _ = control.Read(b[:])
		relay.Close()
	}()
	success = true
	return conn, nil
}

type proxyUDP struct {
	net.Conn
	control           net.Conn
	target            statute.AddrSpec
	header            []byte
	limit             int
	readMu, writeMu   sync.Mutex
	readBuf, writeBuf []byte
	done              chan struct{}
	closeOnce         sync.Once
}

func (c *proxyUDP) Read(data []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readBuf == nil {
		c.readBuf = make([]byte, 65535)
	}
	for {
		n, err := c.Conn.Read(c.readBuf)
		if err != nil {
			return 0, err
		}
		packet, err := socksudp.Parse(c.readBuf[:n])
		if err != nil {
			continue
		}
		if packet.DstAddr.Port != c.target.Port || c.target.IP != nil && !packet.DstAddr.IP.Equal(c.target.IP) || packet.DstAddr.FQDN != "" && packet.DstAddr.FQDN != c.target.FQDN {
			continue
		}
		return copy(data, packet.Data), nil
	}
}

func (c *proxyUDP) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	size := len(c.header) + len(data)
	if size > c.limit {
		return 0, io.ErrShortBuffer
	}
	if cap(c.writeBuf) < size {
		c.writeBuf = make([]byte, size)
	}
	packet := c.writeBuf[:size]
	copy(packet, c.header)
	copy(packet[len(c.header):], data)
	n, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != size {
		return 0, io.ErrShortWrite
	}
	return len(data), nil
}

func (c *proxyUDP) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.control.Close()
		err = c.Conn.Close()
		<-c.done
	})
	return err
}
