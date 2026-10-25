//go:build linux

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/platform/linux/dialer"

var bindInterface = native.BindInterface
