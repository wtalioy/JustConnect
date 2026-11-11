//go:build windows

package privatefile

import native "github.com/wtalioy/JustConnect/corelib/internal/privatefile/windows"

var open = native.Open
