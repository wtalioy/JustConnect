//go:build linux

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/networkstate/linux"

var readRoutes = native.ReadRoutes
var readPolicyRules = native.ReadPolicyRules
var ObserveProxyTunnel = native.ObserveProxyTunnel
