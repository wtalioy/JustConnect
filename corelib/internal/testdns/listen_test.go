package testdns

import (
	"errors"
	"net"
	"testing"
)

func TestOccupiedUDPReleasesTCPBeforeReselectingPair(t *testing.T) {
	occupiedTCP, occupiedUDP := ListenPair(t, "127.0.0.1")
	calls := 0
	tcp, udp := listenPair(t, func() (net.Listener, error) {
		calls++
		if calls == 1 {
			return occupiedTCP, nil
		}
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	if calls < 2 || tcp.Addr().String() != udp.LocalAddr().String() || tcp.Addr().String() == occupiedUDP.LocalAddr().String() {
		t.Fatal("occupied UDP was not replaced with one fully reserved pair")
	}
	if _, err := occupiedTCP.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed pairing retained its first TCP listener", err)
	}
	rebound, err := net.Listen("tcp4", occupiedUDP.LocalAddr().String())
	if err != nil {
		t.Fatal("failed pair still reserves TCP", err)
	}
	rebound.Close()
	tcp.Close()
	udp.Close()
	rebound, err = net.Listen("tcp4", tcp.Addr().String())
	if err != nil {
		t.Fatal("selected TCP pair was not released", err)
	}
	rebound.Close()
	packet, err := net.ListenPacket("udp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal("selected UDP pair was not released", err)
	}
	packet.Close()
}
