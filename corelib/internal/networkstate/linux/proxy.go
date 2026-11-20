//go:build linux

package networkstate

import (
	"encoding/binary"
	"syscall"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/unix"
)

// ObserveProxyTunnel confirms the live link's kernel type and snapshot identity.
func ObserveProxyTunnel(snapshot model.Snapshot, name string) *model.ProxyTunnel {
	for _, device := range snapshot.Interfaces {
		if device.Name != name || device.Index <= 0 || !device.Up || device.Loopback {
			continue
		}
		links, err := netlinkMessages(unix.RTM_GETLINK, unix.AF_UNSPEC)
		if err != nil {
			return nil
		}
		for _, link := range links {
			if matchesTunLink(link, device.Index, name) {
				return &model.ProxyTunnel{InterfaceIndex: device.Index, Name: name}
			}
		}
		return nil
	}
	return nil
}

func matchesTunLink(link syscall.NetlinkMessage, index int, name string) bool {
	if link.Header.Type != unix.RTM_NEWLINK || len(link.Data) < unix.SizeofIfInfomsg ||
		int(int32(binary.NativeEndian.Uint32(link.Data[4:8]))) != index {
		return false
	}
	flags := binary.NativeEndian.Uint32(link.Data[8:12])
	if flags&(unix.IFF_UP|unix.IFF_POINTOPOINT|unix.IFF_LOOPBACK) != unix.IFF_UP|unix.IFF_POINTOPOINT {
		return false
	}
	attrs := link.Data[unix.SizeofIfInfomsg:]
	if string(linkAttribute(attrs, unix.IFLA_IFNAME)) != name+"\x00" {
		return false
	}
	info := linkAttribute(attrs, unix.IFLA_LINKINFO)
	if string(linkAttribute(info, unix.IFLA_INFO_KIND)) != "tun\x00" {
		return false
	}
	data := linkAttribute(info, unix.IFLA_INFO_DATA)
	kind := linkAttribute(data, unix.IFLA_TUN_TYPE)
	return len(kind) == 1 && kind[0] == unix.IFF_TUN
}

func linkAttribute(attrs []byte, target uint16) []byte {
	for len(attrs) > 0 {
		kind, value, rest, err := nextAttribute(attrs)
		if err != nil {
			return nil
		}
		if kind&^unix.NLA_F_NESTED == target {
			return value
		}
		attrs = rest
	}
	return nil
}
