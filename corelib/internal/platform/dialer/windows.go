//go:build windows

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/windows/dialer"

var bindInterface = native.BindInterface
