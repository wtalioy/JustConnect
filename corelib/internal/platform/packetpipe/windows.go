//go:build windows

package packetpipe

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/platform/windows/packetpipe"
	"net/netip"
)

const Supported = true

func Duplicate(value uint64, serverPID uint32, mtu uint32, local, peer netip.Addr) (*Device, error) {
	stream, err := native.Duplicate(value, serverPID)
	if err != nil {
		return nil, err
	}
	device, err := New(stream, mtu, local, peer)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return device, nil
}
