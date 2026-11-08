//go:build darwin

package networkstate

import (
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDefaultIPv4RoutePreservesFirstUpGateway(t *testing.T) {
	makeRoute := func(index, flags int, destination, mask route.Addr) *route.RouteMessage {
		addresses := make([]route.Addr, unix.RTAX_NETMASK+1)
		addresses[unix.RTAX_DST] = destination
		addresses[unix.RTAX_NETMASK] = mask
		return &route.RouteMessage{Index: index, Flags: flags, Addrs: addresses}
	}
	zero := &route.Inet4Addr{}
	const gateway = unix.RTF_UP | unix.RTF_GATEWAY
	messages := []route.Message{
		makeRoute(1, unix.RTF_GATEWAY, zero, zero),
		makeRoute(2, unix.RTF_UP, zero, zero),
		makeRoute(3, gateway, &route.Inet6Addr{}, &route.Inet6Addr{}),
		makeRoute(4, gateway, zero, &route.Inet4Addr{IP: [4]byte{128}}),
		makeRoute(5, gateway, zero, nil),
	}
	if got := defaultIPv4RouteIndex(messages); got != 0 {
		t.Fatalf("invalid default interface selected: %d", got)
	}
	messages = append(messages,
		makeRoute(6, gateway|unix.RTF_IFSCOPE, zero, zero),
		makeRoute(7, gateway, zero, zero))
	if got := defaultIPv4RouteIndex(messages); got != 6 {
		t.Fatalf("default route order changed: %d", got)
	}
}
