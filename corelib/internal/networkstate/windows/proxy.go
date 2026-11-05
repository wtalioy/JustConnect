//go:build windows

package networkstate

import (
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/windows"
)

func ObserveProxyTunnel(snapshot model.Snapshot, name string) *model.ProxyTunnel {
	for _, iface := range snapshot.Interfaces {
		if !iface.Up || iface.Loopback || iface.Index <= 0 || !strings.EqualFold(iface.Name, name) {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
		if windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row) != nil {
			return nil
		}
		// Wintun registers an IP-only virtual miniport, independently of the configured adapter alias.
		const ifTypePropVirtual, ndisMediumIP = 53, 19
		if row.Type == ifTypePropVirtual && row.MediaType == ndisMediumIP && row.OperStatus == windows.IfOperStatusUp &&
			strings.EqualFold(windows.UTF16ToString(row.Alias[:]), name) {
			return &model.ProxyTunnel{InterfaceIndex: iface.Index, Name: iface.Name}
		}
	}
	return nil
}
