//go:build darwin

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/networkstate/macos"

var readRoutes = native.ReadRoutes
