//go:build linux

package networkstate

import (
	"encoding/binary"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProxyTunnelRequiresLiveTunIdentity(t *testing.T) {
	const flags = unix.IFF_UP | unix.IFF_POINTOPOINT
	for _, tc := range []struct {
		label, kind, kernelName string
		mode                    byte
		flags                   uint32
		index                   int
		want                    bool
	}{
		{"custom TUN name", "tun", "Mihomo", unix.IFF_TUN, flags, 17, true},
		{"replaced interface", "tun", "Mihomo", unix.IFF_TUN, flags, 18, false},
		{"renamed interface", "tun", "other", unix.IFF_TUN, flags, 17, false},
		{"inactive TUN", "tun", "Mihomo", unix.IFF_TUN, unix.IFF_POINTOPOINT, 17, false},
		{"TAP", "tun", "Mihomo", unix.IFF_TAP, flags, 17, false},
		{"other point-to-point", "wireguard", "Mihomo", unix.IFF_TUN, flags, 17, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			data := make([]byte, unix.SizeofIfInfomsg)
			binary.NativeEndian.PutUint32(data[4:], uint32(tc.index))
			binary.NativeEndian.PutUint32(data[8:], tc.flags)
			data = append(data, encodeRouteAttribute(unix.IFLA_IFNAME, []byte(tc.kernelName+"\x00"))...)
			info := encodeRouteAttribute(unix.IFLA_INFO_KIND, []byte(tc.kind+"\x00"))
			deviceType := encodeRouteAttribute(unix.IFLA_TUN_TYPE, []byte{tc.mode})
			info = append(info, encodeRouteAttribute(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, deviceType)...)
			data = append(data, encodeRouteAttribute(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
			link := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK}, Data: data}
			if got := matchesTunLink(link, 17, "Mihomo"); got != tc.want {
				t.Fatalf("matchesTunLink() = %v, want %v", got, tc.want)
			}
		})
	}
}
