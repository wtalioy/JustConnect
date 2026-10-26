// Package testdns contains DNS fixtures; production code must not import it.
package testdns

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

const maxPairAttempts = 8

// ListenPair reserves the same kernel-selected port for TCP and UDP.
func ListenPair(t testing.TB, address string) (net.Listener, net.PacketConn) {
	t.Helper()
	return listenPair(t, func() (net.Listener, error) {
		return net.Listen("tcp4", net.JoinHostPort(address, "0"))
	})
}

func listenPair(t testing.TB, listenTCP func() (net.Listener, error)) (net.Listener, net.PacketConn) {
	t.Helper()
	var err error
	// A TCP ephemeral allocation does not reserve its corresponding UDP port.
	for range maxPairAttempts {
		var tcp net.Listener
		tcp, err = listenTCP()
		if err != nil {
			t.Fatal(err)
		}
		var udp net.PacketConn
		udp, err = net.ListenPacket("udp4", tcp.Addr().String())
		if err == nil {
			t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
			return tcp, udp
		}
		_ = tcp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	t.Fatalf("cannot reserve a TCP/UDP DNS pair: %v", err)
	return nil, nil
}
