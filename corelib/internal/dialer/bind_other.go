//go:build !linux && !darwin && !windows

package dialer

import (
	"errors"
	"net"
)

func bindInterface(_ *net.Dialer, _ string) error {
	return nil
}

func sendBufferSize(uintptr) (int, error) {
	return 0, errors.New("native UDP buffer inspection is unsupported")
}
