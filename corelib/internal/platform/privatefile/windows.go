//go:build windows

package privatefile

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/windows/privatefile"

var open = native.Open
