//go:build windows

package dialer

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/dialer/windows"
	"golang.org/x/sys/windows"
)

var bindInterface = native.BindInterface

func sendBufferSize(fd uintptr) (int, error) {
	return windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
}
