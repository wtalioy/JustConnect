package bridge

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"
)

// AttachTUN takes ownership only after binding the device to the ready generation.
func (e *Engine) AttachTUN(handle, generation uint64, device io.ReadWriteCloser, mtu uint32, publishDNS bool) Status {
	if generation == 0 || device == nil {
		return InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return InvalidHandle
	}
	if !s.running || s.stopping || s.generation != generation {
		return StaleRequest
	}
	if !s.connectOperation {
		return Unsupported
	}
	if !s.ready {
		return Busy
	}
	if s.protocol == nil {
		return Unsupported
	}
	var publish func(context.Context, []netip.Addr) error
	if publishDNS {
		publish = func(ctx context.Context, addresses []netip.Addr) error {
			status := s.publishDNSRoutes(ctx, generation, addresses, 5*time.Second)
			if status != OK {
				return errors.New(status.Message())
			}
			return nil
		}
	}
	if err := s.protocol.AttachTUN(device, mtu, publish); err != nil {
		return InvalidArgument
	}
	return OK
}
