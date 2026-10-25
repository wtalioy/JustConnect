//go:build darwin

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/macos/dialer"

var bindInterface = native.BindInterface
