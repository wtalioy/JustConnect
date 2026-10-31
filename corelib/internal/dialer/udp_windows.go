//go:build windows

package dialer

import "golang.org/x/sys/windows"

func sendBufferSize(fd uintptr) (int, error) {
	return windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
}
