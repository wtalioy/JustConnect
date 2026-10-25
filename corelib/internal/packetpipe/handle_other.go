//go:build !windows

package packetpipe

import (
	"errors"
	"net/netip"
)

const Supported = false

func Duplicate(uint64, uint32, uint32, netip.Addr, netip.Addr) (*Device, error) {
	return nil, errors.New("Windows helper packet pipes are unavailable")
}
