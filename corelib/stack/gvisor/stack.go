package gvisor

import (
	"errors"
	"io"
	"net"
	"sync"

	clientpkg "github.com/wtalioy/JustConnect/corelib/client"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Stack struct {
	gvisorStack *stack.Stack
	endpoint    *Endpoint
	ipMu        sync.Mutex
	ip          tcpip.Address
	closed      bool
	errors      chan error
	readDone    chan struct{}
	closeOnce   sync.Once
}

const NICID tcpip.NICID = 1
const MTU uint32 = 1400
const maxInboundPacketSize = 1500

type Endpoint struct {
	client     clientpkg.Client
	l3Conn     io.ReadWriteCloser
	dispatcher stack.NetworkDispatcher
	fail       func(error)
}

func (*Endpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (*Endpoint) MTU() uint32                                  { return MTU }
func (*Endpoint) SetMTU(uint32)                                {}
func (*Endpoint) MaxHeaderLength() uint16                      { return 0 }
func (*Endpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (*Endpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (*Endpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (ep *Endpoint) Attach(dispatcher stack.NetworkDispatcher) { ep.dispatcher = dispatcher }
func (ep *Endpoint) IsAttached() bool                          { return ep.dispatcher != nil }
func (*Endpoint) Wait()                                        {}
func (*Endpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (*Endpoint) AddHeader(*stack.PacketBuffer)                {}
func (*Endpoint) Close()                                       {}
func (*Endpoint) SetOnCloseAction(func())                      {}

func (ep *Endpoint) WritePackets(list stack.PacketBufferList) (written int, result tcpip.Error) {
	defer func() {
		if recover() != nil {
			ep.fail(errors.New("network stack writer panicked"))
			result = &tcpip.ErrAborted{}
		}
	}()
	for _, packet := range list.AsSlice() {
		if _, err := ep.l3Conn.Write(joinPacketSlices(packet.AsSlices())); err != nil {
			if errors.Is(err, clientpkg.ErrResourceNotFound) {
				written++
				continue
			}
			ep.fail(err)
			return written, &tcpip.ErrAborted{}
		}
		written++
	}
	return written, nil
}

func joinPacketSlices(slices [][]byte) []byte {
	total := 0
	for _, part := range slices {
		total += len(part)
	}
	buf := make([]byte, total)
	offset := 0
	for _, part := range slices {
		offset += copy(buf[offset:], part)
	}
	return buf
}

func NewStack(client clientpkg.Client) (*Stack, error) {
	s := &Stack{errors: make(chan error, 1), readDone: make(chan struct{})}
	s.gvisorStack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}, HandleLocal: true})
	success := false
	defer func() {
		if !success {
			if s.endpoint != nil && s.endpoint.l3Conn != nil {
				_ = s.endpoint.l3Conn.Close()
			}
			s.gvisorStack.Close()
			s.gvisorStack.Wait()
		}
	}()
	s.endpoint = &Endpoint{client: client, fail: s.fail}
	conn, err := client.NewL3Conn()
	if err != nil {
		return nil, err
	}
	s.endpoint.l3Conn = conn
	if err := s.gvisorStack.CreateNIC(NICID, s.endpoint); err != nil {
		return nil, errors.New(err.String())
	}
	ip, err := client.IP()
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, errors.New("virtual IP is not IPv4")
	}
	s.ip = tcpip.AddrFromSlice(ip.To4())
	protoAddr := tcpip.ProtocolAddress{AddressWithPrefix: tcpip.AddressWithPrefix{Address: s.ip, PrefixLen: 32}, Protocol: ipv4.ProtocolNumber}
	if err := s.gvisorStack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, errors.New(err.String())
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, errors.New(err.String())
	}
	congestion := tcpip.CongestionControlOption("cubic")
	if err := s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &congestion); err != nil {
		return nil, errors.New(err.String())
	}
	s.gvisorStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: NICID})
	clientpkg.RegisterIPUpdateHandler(client, s.updateIP)
	success = true
	go s.readLoop()
	return s, nil
}

func (s *Stack) fail(err error) {
	select {
	case s.errors <- err:
	default:
	}
}
func (s *Stack) Errors() <-chan error { return s.errors }

func (s *Stack) readLoop() {
	defer close(s.readDone)
	defer func() {
		if recover() != nil {
			s.fail(errors.New("network stack reader panicked"))
		}
	}()
	buf := make([]byte, maxInboundPacketSize)
	for {
		n, err := s.endpoint.l3Conn.Read(buf)
		if err != nil {
			s.fail(err)
			return
		}
		packet := makeInboundPacketBuffer(buf, n)
		s.endpoint.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packet)
		packet.DecRef()
	}
}

func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		s.ipMu.Lock()
		s.closed = true
		s.ipMu.Unlock()
		clientpkg.RegisterIPUpdateHandler(s.endpoint.client, nil)
		_ = s.endpoint.l3Conn.Close()
		<-s.readDone
		s.gvisorStack.Close()
		s.gvisorStack.Wait()
	})
}

func (s *Stack) updateIP(ip net.IP) error {
	ip = ip.To4()
	if ip == nil {
		return errors.New("virtual IP update is not IPv4")
	}
	addr := tcpip.AddrFromSlice(ip)
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if addr == s.ip {
		return nil
	}
	protoAddr := tcpip.ProtocolAddress{AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 32}, Protocol: ipv4.ProtocolNumber}
	if err := s.gvisorStack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{}); err != nil {
		return errors.New(err.String())
	}
	if err := s.gvisorStack.RemoveAddress(NICID, s.ip); err != nil {
		_ = s.gvisorStack.RemoveAddress(NICID, addr)
		return errors.New(err.String())
	}
	s.ip = addr
	return nil
}

func makeInboundPacketBuffer(buf []byte, n int) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
}
