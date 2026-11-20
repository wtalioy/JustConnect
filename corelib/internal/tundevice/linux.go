//go:build linux

package tundevice

import native "github.com/wtalioy/JustConnect/corelib/internal/tundevice/linux"

const Supported = true

var Duplicate = native.Duplicate
