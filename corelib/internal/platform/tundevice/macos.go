//go:build darwin

package tundevice

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/macos/utun"

const Supported = true

var Duplicate = native.Duplicate
