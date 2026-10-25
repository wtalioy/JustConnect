//go:build windows

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/dialer/windows"

var bindInterface = native.BindInterface
