//go:build darwin

package dialer

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/dialer/macos"
	"golang.org/x/sys/unix"
)

var bindInterface = native.BindInterface

func sendBufferSize(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}
