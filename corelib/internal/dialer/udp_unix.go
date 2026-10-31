//go:build linux || darwin

package dialer

import "golang.org/x/sys/unix"

func sendBufferSize(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}
