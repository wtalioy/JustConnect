package service

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunNIC = 1
	// Bound pending handshakes, active relays and queued response packets.
	maxTUNFlows       = 256
	tunUDPIdleTimeout = 90 * time.Second
)

type tunFlow struct {
	protocol tcpip.TransportProtocolNumber
	id       stack.TransportEndpointID
}

type tunIngress struct {
	owner   *Listeners
	device  io.ReadWriteCloser
	stack   *stack.Stack
	link    *channel.Endpoint
	mu      sync.Mutex
	closed  bool
	flows   map[tunFlow]struct{}
	workers sync.WaitGroup
	pumps   sync.WaitGroup
}

// AttachTUN takes ownership on success. Each read/write is one raw IPv4 packet;
// Close must interrupt device I/O. Address, routes and DNS belong to the helper.
func (p *Listeners) AttachTUN(device io.ReadWriteCloser, mtu uint32) error {
	if device == nil || mtu < header.IPv4MinimumProcessableDatagramSize || mtu > maxUDPPacket {
		return errors.New("invalid IPv4 TUN device or MTU")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if p.tun != nil || p.dialer == nil {
		return errors.New("TUN requires a dialer and a single device owner")
	}
	i := &tunIngress{owner: p, device: device, flows: make(map[tunFlow]struct{})}
	i.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	i.link = channel.New(maxTUNFlows, mtu, "")
	if err := i.stack.CreateNIC(tunNIC, i.link); err != nil {
		i.link.Close()
		i.stack.Close()
		i.stack.Wait()
		return errors.New(err.String())
	}
	// Captured destinations are remote campus addresses, never local NIC addresses.
	_ = i.stack.SetPromiscuousMode(tunNIC, true)
	_ = i.stack.SetSpoofing(tunNIC, true)
	i.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tunNIC})
	forwarder := tcp.NewForwarder(i.stack, 0, maxTUNFlows, i.forwardTCP)
	i.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		key := tunFlow{tcp.ProtocolNumber, id}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.closed || len(i.flows) >= maxTUNFlows {
			return true
		}
		if _, exists := i.flows[key]; exists {
			return true
		}
		i.flows[key] = struct{}{}
		i.workers.Add(1)
		if !forwarder.HandlePacket(id, packet) {
			delete(i.flows, key)
			i.workers.Done()
			return false
		}
		return true
	})
	i.stack.SetTransportProtocolHandler(udp.ProtocolNumber, i.forwardUDP)
	p.tun = i
	i.pumps.Add(2)
	go func() { defer i.pumps.Done(); defer p.recoverWorker(); i.readPackets(mtu) }()
	go func() { defer i.pumps.Done(); defer p.recoverWorker(); i.writePackets() }()
	return nil
}

func (i *tunIngress) release(key tunFlow) {
	i.mu.Lock()
	delete(i.flows, key)
	i.mu.Unlock()
	i.workers.Done()
}

func (i *tunIngress) dial(protocol string, id stack.TransportEndpointID) (net.Conn, error) {
	address := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	conn, err := i.owner.dialer.DialCampusIPPort(i.owner.ctx, protocol, address)
	if err != nil {
		return nil, err
	}
	return i.owner.own(conn)
}

func (i *tunIngress) forwardTCP(request *tcp.ForwarderRequest) {
	defer i.release(tunFlow{tcp.ProtocolNumber, request.ID()})
	defer i.owner.recoverWorker()
	completed := false
	defer func() {
		if !completed {
			request.Complete(true)
		}
	}()
	target, err := i.dial("tcp", request.ID())
	if err != nil {
		return
	}
	defer target.Close()
	var queue waiter.Queue
	endpoint, tcpErr := request.CreateEndpoint(&queue)
	if tcpErr != nil {
		return
	}
	request.Complete(false)
	completed = true
	guest, err := i.owner.own(gonet.NewTCPConn(&queue, endpoint))
	if err != nil {
		return
	}
	defer guest.Close()
	relayStream(guest, guest, target, i.owner.fail)
}

func (i *tunIngress) forwardUDP(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
	key := tunFlow{udp.ProtocolNumber, id}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || len(i.flows) >= maxTUNFlows {
		return true
	}
	if _, exists := i.flows[key]; exists {
		return true
	}
	var queue waiter.Queue
	// Synchronous endpoint creation consumes the borrowed first packet.
	endpoint, err := udp.NewForwarderRequest(i.stack, id, packet).CreateEndpoint(&queue)
	if err != nil {
		return false
	}
	guest, ownErr := i.owner.own(gonet.NewUDPConn(&queue, endpoint))
	if ownErr != nil {
		return true
	}
	i.flows[key] = struct{}{}
	i.workers.Add(1)
	go func() {
		defer i.release(key)
		defer i.owner.recoverWorker()
		defer guest.Close()
		target, err := i.dial("udp", id)
		if err != nil {
			return
		}
		defer target.Close()
		relayDatagrams(guest, target, tunUDPIdleTimeout, i.owner.fail)
	}()
	return true
}

func relayDatagrams(left, right net.Conn, idle time.Duration, fail func(error)) {
	refresh := func() {
		deadline := time.Now().Add(idle)
		_ = left.SetDeadline(deadline)
		_ = right.SetDeadline(deadline)
	}
	refresh()
	copyPackets := func(dst, src net.Conn) {
		defer func() { _ = left.Close(); _ = right.Close() }()
		defer func() {
			if recover() != nil {
				fail(errors.New("TUN datagram relay panicked"))
			}
		}()
		buf := make([]byte, maxUDPPacket)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			refresh()
			if written, err := dst.Write(buf[:n]); err != nil || written != n {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); copyPackets(left, right) }()
	copyPackets(right, left)
	<-done
}

func (i *tunIngress) readPackets(mtu uint32) {
	buf := make([]byte, mtu+1)
	for {
		n, err := i.device.Read(buf)
		if err != nil {
			i.deviceFailure("read", err)
			return
		}
		if n < header.IPv4MinimumSize || n > int(mtu) || header.IPVersion(buf[:n]) != 4 {
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
		i.link.InjectInbound(ipv4.ProtocolNumber, packet)
		packet.DecRef()
	}
}

func (i *tunIngress) writePackets() {
	for {
		packet := i.link.ReadContext(i.owner.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		data := view.AsSlice()
		n, err := i.device.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		view.Release()
		packet.DecRef()
		if err != nil {
			i.deviceFailure("write", err)
			return
		}
	}
}

func (i *tunIngress) deviceFailure(operation string, err error) {
	if i.owner.ctx.Err() == nil {
		i.owner.fail(&net.OpError{Op: operation, Net: "tun", Err: err})
	}
}

func (i *tunIngress) close() {
	i.mu.Lock()
	i.closed = true
	i.mu.Unlock()
	_ = i.device.Close()
	i.link.Close()
	i.pumps.Wait()
	_ = i.stack.RemoveNIC(tunNIC)
	done := make(chan struct{})
	go func() { i.workers.Wait(); close(done) }()
	// A forwarder may register its handshake after shutdown started.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, endpoint := range i.stack.RegisteredEndpoints() {
			endpoint.Abort()
		}
		select {
		case <-done:
			i.stack.Close()
			i.stack.Wait()
			return
		case <-ticker.C:
		}
	}
}
