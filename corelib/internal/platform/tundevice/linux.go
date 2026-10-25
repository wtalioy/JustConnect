//go:build linux

package tundevice

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/linux/tun"

const Supported = true

var Duplicate = native.Duplicate
