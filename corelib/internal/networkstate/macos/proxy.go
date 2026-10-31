//go:build darwin

package networkstate

import (
	"net"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
)

func ObserveProxyTunnel(snapshot model.Snapshot, name string) *model.ProxyTunnel {
	number, ok := strings.CutPrefix(name, "utun")
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
