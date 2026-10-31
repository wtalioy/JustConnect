package dnslistener

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestOccupiedTCPReleasesUDPBeforeReselectingPair(t *testing.T) {
	occupiedTCP, occupiedUDP, err := Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedTCP.Close()
	defer occupiedUDP.Close()
	calls := 0
	tcp, udp, err := listenPair(t.Context(), "127.0.0.1:0", func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
		calls++
		if calls == 1 {
			return occupiedUDP, nil
		}
		return net.ListenUDP(network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	if calls < 2 || tcp.Addr().String() != udp.LocalAddr().String() || tcp.Addr().String() == occupiedTCP.Addr().String() {
		t.Fatal("occupied TCP was not replaced with one fully reserved pair")
	}
	if _, _, err := occupiedUDP.ReadFromUDPAddrPort(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed pairing retained its first UDP socket", err)
	}
	reboundUDP, err := net.ListenPacket("udp4", occupiedTCP.Addr().String())
	if err != nil {
		t.Fatal("failed pair still reserves UDP", err)
	}
	reboundUDP.Close()
	tcp.Close()
	udp.Close()
	reboundTCP, err := net.Listen("tcp4", tcp.Addr().String())
	if err != nil {
		t.Fatal("selected TCP pair was not released", err)
	}
	reboundTCP.Close()
	reboundUDP, err = net.ListenPacket("udp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal("selected UDP pair was not released", err)
	}
	reboundUDP.Close()
}

func TestExplicitTCPConflictReleasesUDPWithoutChangingPort(t *testing.T) {
	tcp, udp, err := Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp.Close()
	otherTCP, otherUDP, err := Listen(t.Context(), tcp.Addr().String())
	if err == nil || otherTCP != nil || otherUDP != nil {
		t.Fatal("explicit occupied TCP port was replaced or exposed partial listeners", err)
	}
	rebound, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal("explicit pairing failure retained UDP", err)
	}
	rebound.Close()
}

func TestCancelledPairDoesNotOpenSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tcp, udp, err := Listen(ctx, "127.0.0.1:0")
	if !errors.Is(err, context.Canceled) || tcp != nil || udp != nil {
		t.Fatal("cancelled DNS allocation returned owned sockets", err)
	}
}

func TestExcludedUDPSelectionUsesTCPAllocatorWithoutGuessingPort(t *testing.T) {
	occupied, availableUDP, err := Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	defer availableUDP.Close()
	firstUDP := availableUDP
	usedTCPAllocator := false
	tcp, udp, err := listenPair(t.Context(), "127.0.0.1:0", func(network string, address *net.UDPAddr) (*net.UDPConn, error) {
		if firstUDP != nil && address.Port == 0 {
			// Hand over an already bound candidate; rebinding can itself be excluded.
			candidate := firstUDP
			firstUDP = nil
			return candidate, nil
		}
		if address.Port != 0 {
			usedTCPAllocator = true
		}
		return net.ListenUDP(network, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	if !usedTCPAllocator || tcp.Addr().String() != udp.LocalAddr().String() || tcp.Addr().String() == occupied.Addr().String() {
		t.Fatal("excluded UDP candidates did not use the TCP kernel allocator")
	}
	if _, _, err := availableUDP.ReadFromUDPAddrPort(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("abandoned UDP candidate retained its socket", err)
	}
}
