//go:build linux

package dialer

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// BindInterface pins a dialer to one network interface.
//
// SO_BINDTODEVICE requires CAP_NET_RAW for sockets owned by unprivileged
// users; the tunnel runtime grants it to the trusted helper binary. Ordinary
// callers keep the interface unset and follow the default routing table.
func BindInterface(dialer *net.Dialer, interfaceName string) error {
	if len(interfaceName) >= unix.IFNAMSIZ {
		return errors.New("interface name exceeds IFNAMSIZ")
	}
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return err
	}
	dialer.ControlContext = func(_ context.Context, _, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			// SO_BINDTODEVICE matches IPv4 and IPv6 on the same socket and
			// keeps the pin applied to every address family the dialer uses.
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}
