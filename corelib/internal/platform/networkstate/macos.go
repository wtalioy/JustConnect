//go:build darwin

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/macos/networkstate"

var readRoutes = native.ReadRoutes
