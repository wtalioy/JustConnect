package bridge

import (
	"context"
	"math"
	"net/netip"
	"time"
)

type pendingDNSRoutes struct {
	id        uint64
	ctx       context.Context
	delivered bool
	result    chan bool
}

// One request owns the event slot until acknowledged, expired or cancelled.
func (s *Session) publishDNSRoutes(parent context.Context, generation uint64, addresses []netip.Addr, exclude bool, wait time.Duration) Status {
	s.mu.Lock()
	if !s.running || s.stopping || generation != s.generation {
		s.mu.Unlock()
		return Cancelled
	}
	stopped := s.ctx.Done()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, wait)
	defer cancel()
	select {
	case s.dnsRouteGate <- struct{}{}:
		defer func() { <-s.dnsRouteGate }()
	case <-stopped:
		return Cancelled
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return Timeout
		}
		return Cancelled
	}
	s.mu.Lock()
	if ctx.Err() == context.DeadlineExceeded {
		s.mu.Unlock()
		return Timeout
	}
	if ctx.Err() != nil || !s.running || s.stopping || generation != s.generation {
		s.mu.Unlock()
		return Cancelled
	}
	if s.nextRequest == math.MaxUint64 || s.sequence >= math.MaxUint64-1 {
		s.mu.Unlock()
		return Limit
	}
	values := make([]string, len(addresses))
	for index, address := range addresses {
		values[index] = address.String()
	}
	// Recheck after serialization: an earlier original reply may have withdrawn this address.
	if !exclude && s.protocol != nil {
		wanted := make(map[string]struct{}, len(values))
		for _, address := range values {
			wanted[address] = struct{}{}
		}
		for name, original := range s.protocol.OriginalDNSRecords() {
			if s.policy != nil {
				if allowed, protected := s.policy.CampusNameAllowed(name); protected && allowed {
					continue
				}
			}
			for _, address := range original {
				if _, found := wanted[address]; found {
					s.mu.Unlock()
					return NetworkFailure
				}
			}
		}
	}
	s.nextRequest++
	pending := &pendingDNSRoutes{id: s.nextRequest, ctx: ctx, result: make(chan bool, 1)}
	if status := s.push(event{Type: "dns_routes", RequestID: pending.id, Addresses: values, Exclude: exclude}); status != OK {
		s.mu.Unlock()
		return status
	}
	s.dnsRoutes = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.dnsRoutes == pending {
			s.dnsRoutes = nil
		}
		for index, item := range s.queue {
			if item.request == pending.id {
				copy(s.queue[index:], s.queue[index+1:])
				s.queue[len(s.queue)-1] = queued{}
				s.queue = s.queue[:len(s.queue)-1]
				break
			}
		}
	}()
	select {
	case applied := <-pending.result:
		if ctx.Err() == nil {
			select {
			case <-stopped:
				return Cancelled
			default:
				if applied {
					return OK
				}
				return NetworkFailure
			}
		}
	case <-ctx.Done():
	case <-stopped:
		return Cancelled
	}
	if ctx.Err() == context.DeadlineExceeded {
		return Timeout
	}
	return Cancelled
}

func (e *Engine) AcknowledgeDNSRoutes(handle, generation, request uint64, applied bool) Status {
	if generation == 0 || request == 0 {
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
	pending := s.dnsRoutes
	if !s.running || s.stopping || s.generation != generation || pending == nil ||
		pending.id != request || pending.ctx.Err() != nil || !pending.delivered {
		return StaleRequest
	}
	s.dnsRoutes = nil
	pending.result <- applied
	return OK
}
