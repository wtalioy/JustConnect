//go:build windows

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/networkstate/windows"

var readRoutes = native.ReadRoutes
var readInterfaces = native.ReadInterfaces
var DefaultIPv4Interface = native.DefaultIPv4Interface
var ObserveProxyTunnel = native.ObserveProxyTunnel
