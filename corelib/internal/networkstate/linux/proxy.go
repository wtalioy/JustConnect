//go:build linux

package networkstate

import (
	"net"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
)

// ObserveProxyTunnel confirms that a snapshot interface is the live TUN device.
// Linux TUN devices keep the tun<N> naming the privileged helper assigns.
func ObserveProxyTunnel(snapshot model.Snapshot, name string) *model.ProxyTunnel {
	number, ok := strings.CutPrefix(name, "tun")
	if !ok || number == "" || strings.Trim(number, "0123456789") != "" {
		return nil
	}
	for _, device := range snapshot.Interfaces {
		if device.Name != name || !device.Up || device.Loopback {
			continue
		}
		actual, err := net.InterfaceByName(name)
		if err == nil && actual.Index == device.Index && actual.Flags&(net.FlagUp|net.FlagPointToPoint|net.FlagLoopback) == net.FlagUp|net.FlagPointToPoint {
			return &model.ProxyTunnel{InterfaceIndex: device.Index, Name: name}
		}
	}
	return nil
}
