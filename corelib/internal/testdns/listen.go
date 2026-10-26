// Package testdns contains DNS fixtures; production code must not import it.
package testdns

import (
	"net"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
)

// ListenPair reserves the same kernel-selected port for TCP and UDP.
func ListenPair(t testing.TB, address string) (net.Listener, net.PacketConn) {
	t.Helper()
	tcp, udp, err := dnslistener.Listen(t.Context(), net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
	return tcp, udp
}
