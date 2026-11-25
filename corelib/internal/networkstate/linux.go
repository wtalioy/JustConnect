//go:build linux

package networkstate

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/networkstate/linux"
)

var readRoutes = native.ReadRoutes
var readInterfaces = native.ReadInterfaces
var DefaultIPv4Interface = native.DefaultIPv4Interface

var ObserveProxyTunnel = native.ObserveProxyTunnel
