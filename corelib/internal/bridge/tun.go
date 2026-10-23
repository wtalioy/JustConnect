package bridge

import "io"

// AttachTUN takes ownership only after binding the device to the ready generation.
func (e *Engine) AttachTUN(handle, generation uint64, device io.ReadWriteCloser, mtu uint32) Status {
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
	if err := s.protocol.AttachTUN(device, mtu); err != nil {
		return InvalidArgument
	}
	return OK
}
