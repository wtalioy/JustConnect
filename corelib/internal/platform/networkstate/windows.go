//go:build windows

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/windows/networkstate"

var readRoutes = native.ReadRoutes
