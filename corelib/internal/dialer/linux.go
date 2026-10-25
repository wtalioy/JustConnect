//go:build linux

package dialer

import native "github.com/wtalioy/JustConnect/corelib/internal/dialer/linux"

var bindInterface = native.BindInterface
