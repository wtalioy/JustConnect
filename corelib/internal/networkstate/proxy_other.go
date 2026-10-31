//go:build !linux && !darwin

package networkstate

import "github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"

// Other platforms do not export an attested proxy tunnel role.
func ObserveProxyTunnel(model.Snapshot, string) *model.ProxyTunnel { return nil }
