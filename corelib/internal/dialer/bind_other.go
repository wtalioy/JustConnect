//go:build !linux && !darwin && !windows

package dialer

import "net"

func bindInterface(_ *net.Dialer, _ string) error {
	return nil
}
