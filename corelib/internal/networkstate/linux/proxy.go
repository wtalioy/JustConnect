//go:build linux

package networkstate

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/unix"
)

func ObserveProxyTunnel(snapshot model.Snapshot, name string) *model.ProxyTunnel {
	for _, device := range snapshot.Interfaces {
		if device.Name != name || !device.Up || device.Loopback {
			continue
		}
		flags, err := os.ReadFile(filepath.Join("/sys/class/net", device.Name, "tun_flags"))
		if err != nil {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(flags)), 0, 32)
		if err != nil || value&unix.IFF_TUN == 0 {
			continue
		}
		actual, err := net.InterfaceByName(device.Name)
		if err == nil && actual.Index == device.Index {
			return &model.ProxyTunnel{InterfaceIndex: device.Index, Name: device.Name}
		}
	}
	return nil
}
