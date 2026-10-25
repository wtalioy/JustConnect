//go:build linux || darwin || windows

package dialer

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestBoundLoopbackCarriesTCPAndUDP(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) == net.FlagUp|net.FlagLoopback {
			name = iface.Name
			break
		}
	}
	if name == "" {
		t.Fatal("no active loopback interface")
	}
	for _, family := range []struct{ suffix, address string }{{"4", "127.0.0.1:0"}, {"6", "[::1]:0"}} {
		for _, transport := range []string{"tcp", "udp"} {
			network := transport + family.suffix
			t.Run(network, func(t *testing.T) {
				var address string
				if transport == "tcp" {
					listener, err := net.Listen(network, family.address)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					address = listener.Addr().String()
					go func() {
						conn, err := listener.Accept()
						if err == nil {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(3 * time.Second))
							io.Copy(conn, conn)
						}
					}()
				} else {
					listener, err := net.ListenPacket(network, family.address)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					listener.SetReadDeadline(time.Now().Add(3 * time.Second))
					address = listener.LocalAddr().String()
					go func() {
						var packet [32]byte
						if size, peer, err := listener.ReadFrom(packet[:]); err == nil {
							listener.WriteTo(packet[:size], peer)
						}
					}()
				}
				conn, err := (&Dialer{InterfaceName: name}).DialContext(t.Context(), network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = conn.Write([]byte("bound")); err != nil {
					t.Fatal(err)
				}
				var reply [5]byte
				if _, err = io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "bound" {
					t.Fatal("bound socket did not complete an actual exchange", err)
				}
			})
		}
	}
}

func TestInvalidBindingDoesNotFallBackToOriginalRoute(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := (&Dialer{InterfaceName: "justconnect-no-such-interface"}).DialContext(t.Context(), "tcp", listener.Addr().String())
	if conn != nil {
		conn.Close()
	}
	if err == nil || conn != nil {
		t.Fatal("invalid interface silently used the original route", err)
	}
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
	accepted, err := listener.Accept()
	if accepted != nil {
		accepted.Close()
		t.Fatal("binding error still reached the destination")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("could not verify that the destination was not reached", err)
	}
}
