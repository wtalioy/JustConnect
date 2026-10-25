//go:build darwin

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/dialer/macos"

var bindInterface = native.BindInterface
