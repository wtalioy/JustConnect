//go:build darwin

package tundevice

import native "github.com/wtalioy/JustConnect/corelib/internal/tundevice/macos"

const Supported = true

var Duplicate = native.Duplicate
