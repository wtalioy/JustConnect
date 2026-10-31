package macos

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTCPListenerOwnershipRequiresKernelPIDAndListeningEndpoint(t *testing.T) {
	const header = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes rhiwat shiwat process:pid state options gencnt\n"
	for _, test := range []struct {
		name, row, target string
		owned             bool
	}{
		{"owned", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", true},
		{"private process name", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 :123 0 0 0", "127.0.0.1:7897", true},
		{"other PID", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 mihomo:1123 0 0 0", "127.0.0.1:7897", false},
		{"space in foreign process name", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 forged:123 :456 0 0 0", "127.0.0.1:7897", false},
		{"space in owned process name", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 owned process:123 0 0 0", "127.0.0.1:7897", true},
		{"newline in foreign process name", "tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 forged:123 0 0 0\n:456 0 0 0", "127.0.0.1:7897", false},
		{"other port", "tcp4 0 0 127.0.0.1.17897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", false},
		{"connected", "tcp4 0 0 127.0.0.1.7897 *.* ESTABLISHED 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", false},
		{"IPv6", "tcp6 0 0 ::1.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "[::1]:7897", true},
		{"mapped IPv4", "tcp6 0 0 ::ffff:127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", true},
		{"wildcard", "tcp46 0 0 *.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", true},
		{"other family wildcard", "tcp6 0 0 *.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "127.0.0.1:7897", false},
		{"nonloopback target", "tcp4 0 0 *.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0", "192.0.2.1:7897", false},
		{"truncated", "tcp4 0 0 127.0.0.1.7897", "127.0.0.1:7897", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpListenerOwned(strings.NewReader(header+test.row+"\n"), 123, netip.MustParseAddrPort(test.target)); got != test.owned {
				t.Fatalf("ownership = %v, want %v", got, test.owned)
			}
		})
	}
	for _, input := range []string{"tcp4 0 0 127.0.0.1.7897 *.* LISTEN 123\n", "Proto Recv-Q Send-Q Local Address Foreign Address (state)\ntcp4 0 0 127.0.0.1.7897 *.* LISTEN\n"} {
		if tcpListenerOwned(strings.NewReader(input), 123, netip.MustParseAddrPort("127.0.0.1:7897")) {
			t.Fatal("inventory without PID header granted ownership")
		}
	}
	if tcpListenerOwned(strings.NewReader(header+"tcp4 0 0 127.0.0.1.7897 *.* LISTEN 0 0 8192 8192 mihomo:123 0 0 0\n"+header), 123, netip.MustParseAddrPort("127.0.0.1:7897")) {
		t.Fatal("a later header replaced the authenticated inventory shape")
	}
}
