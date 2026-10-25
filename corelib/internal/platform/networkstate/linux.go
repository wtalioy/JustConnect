//go:build linux

package networkstate

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/linux/networkstate"

var readRoutes = native.ReadRoutes
var readPolicyRules = native.ReadPolicyRules
