//go:build !linux

package networkstate

import "github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"

// Only Linux exports the policy-table proxy role in the native snapshot contract.
func ObserveProxyTunnel(model.Snapshot, string) *model.ProxyTunnel { return nil }
