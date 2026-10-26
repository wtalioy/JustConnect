package bridge

import (
	"errors"
	"net"

	"github.com/wtalioy/JustConnect/corelib/resolve"
	"github.com/wtalioy/JustConnect/corelib/service"
)

func compileOriginalDNS(routes []resolve.OriginalDNSRoute) (*resolve.OriginalDNS, error) {
	for _, route := range routes {
		if len(route.Interface) > MaxInterfaceName || len(route.EgressInterface) > MaxInterfaceName {
			return nil, errors.New("original DNS interface exceeds its input bound")
		}
	}
	return resolve.NewOriginalDNS(routes)
}

// PrepareOriginalDNS seals sources once, after authentication and before device attachment.
func (e *Engine) PrepareOriginalDNS(handle uint64, input []byte) (uint64, Status) {
	var request struct {
		SchemaVersion int                        `json:"schema_version"`
		Generation    uint64                     `json:"generation,string"`
		Sources       []resolve.OriginalDNSRoute `json:"sources"`
	}
	if !decode(input, &request) || request.SchemaVersion != ABIVersion || request.Generation == 0 || len(request.Sources) == 0 {
		return 0, InvalidArgument
	}
	original, err := compileOriginalDNS(request.Sources)
	if err != nil {
		return 0, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return 0, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return 0, InvalidHandle
	}
	if !s.running || s.stopping || s.generation != request.Generation {
		return 0, StaleRequest
	}
	if !s.connectOperation {
		return 0, Unsupported
	}
	if !s.ready {
		return 0, Busy
	}
	if s.protocol == nil {
		return 0, Unsupported
	}
	if s.policy == nil {
		return 0, InvalidArgument
	}
	if err := s.protocol.PrepareOriginalDNS(original); err != nil {
		if errors.Is(err, service.ErrOriginalDNSSealed) {
			return 0, Busy
		}
		if errors.Is(err, net.ErrClosed) {
			return 0, Cancelled
		}
		return 0, NetworkFailure
	}
	return s.generation, OK
}
