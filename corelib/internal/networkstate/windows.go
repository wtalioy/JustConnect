//go:build windows

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/networkstate/windows"

var readRoutes = native.ReadRoutes
