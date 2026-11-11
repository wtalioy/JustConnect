package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
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
)

type nativeOriginalPeer struct{ tcp, udp, nonCampusTCP, nonCampusUDP atomic.Int32 }

func startNativeOriginalPeer(t *testing.T, gateway *gateway) *nativeOriginalPeer {
	t.Helper()
	value := os.Getenv("JC_NATIVE_ORIGINAL_FD")
	if value == "" {
		return nil
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 || runtime.GOOS != "darwin" || os.Getenv("JC_NATIVE_NETWORK_POLICY") != "1" {
		t.Fatal("original peer requires the disposable macOS policy fixture")
	}
	device := os.NewFile(uintptr(fd), "original-utun")
	var family [4]byte
	binary.BigEndian.PutUint32(family[:], syscall.AF_INET)
	return serveNativeOriginalPeer(t, gateway, device, family[:])
}

func serveNativeOriginalPeer(t *testing.T, gateway *gateway, device io.ReadWriteCloser, family []byte) *nativeOriginalPeer {
	t.Helper()
	base, _ := gateway.resourceIP.Load().(string)
	address := netip.MustParseAddr(base)
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(32, 1400, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{address.Prev(), address, address.Next()} {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4(ip.As4()).WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	peer := new(nativeOriginalPeer)
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		data := make([]byte, 65536)
		for {
			n, err := device.Read(data)
			if err != nil {
				return
			}
			if n <= len(family) || !bytes.Equal(data[:len(family)], family) {
				continue
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(data[len(family):n]))})
			link.InjectInbound(ipv4.ProtocolNumber, packet)
			packet.DecRef()
		}
	}()
	go func() {
		defer workers.Done()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := append(bytes.Clone(family), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			if _, err := device.Write(data); err != nil {
				return
			}
		}
	}()
	var sockets []io.Closer
	for index, target := range []netip.Addr{address.Next(), address.Prev()} {
		stream, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 80}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		udpTarget := address
		tcpCount, udpCount := &peer.tcp, &peer.udp
		if index == 1 {
			udpTarget = target
			tcpCount, udpCount = &peer.nonCampusTCP, &peer.nonCampusUDP
		}
		datagram, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(udpTarget.As4()), Port: 53}, nil, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, stream, datagram)
		workers.Add(2)
		go func() {
			defer workers.Done()
			for {
				conn, err := stream.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					tcpCount.Add(1)
					if _, err := io.WriteString(conn, "original:"); err == nil {
						io.Copy(conn, conn)
					}
				}()
			}
		}()
		go func() {
			defer workers.Done()
			data := make([]byte, 65536)
			for {
				n, addr, err := datagram.ReadFrom(data)
				if err != nil {
					return
				}
				udpCount.Add(1)
				if _, err := datagram.WriteTo(append([]byte("original:"), data[:n]...), addr); err != nil {
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		for _, socket := range sockets {
			socket.Close()
		}
		device.Close()
		link.Close()
		workers.Wait()
		s.Close()
		s.Wait()
	})
	return peer
}
