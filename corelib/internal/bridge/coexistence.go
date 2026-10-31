package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
)

func (e *Engine) UpdateCoexistence(handle uint64, input []byte) (uint64, Status) {
	var request struct {
		SchemaVersion int                    `json:"schema_version"`
		Generation    uint64                 `json:"generation,string"`
		Endpoints     []string               `json:"system_proxy_endpoints"`
		Managed       *bool                  `json:"system_proxy_managed"`
		Proofs        []mihomo.ListenerProof `json:"listener_proofs,omitempty"`
	}
	if !decode(input, &request) || request.SchemaVersion != ABIVersion || request.Generation == 0 || (request.Endpoints == nil || request.Managed == nil) {
		return 0, InvalidArgument
	}
	seen := make(map[string]struct{}, len(request.Endpoints))
	for _, value := range request.Endpoints {
		endpoint, err := netip.ParseAddrPort(value)
		if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || endpoint.String() != value {
			return 0, InvalidArgument
		}
		if _, ok := seen[value]; ok {
			return 0, InvalidArgument
		}
		seen[value] = struct{}{}
	}
	if len(request.Proofs) > mihomo.MaxListenerProofs {
		return 0, InvalidArgument
	}
	proven := make(map[string]bool, len(request.Proofs))
	for _, proof := range request.Proofs {
		endpoint, err := netip.ParseAddrPort(proof.Endpoint)
		if proof.PID <= 0 || proof.PID > math.MaxInt32 || proof.Started == 0 || proof.Inode == 0 || err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || endpoint.String() != proof.Endpoint || proven[proof.Endpoint] {
			return 0, InvalidArgument
		}
		proven[proof.Endpoint] = true
	}

	s := e.lookup(handle)
	if s == nil {
		return 0, InvalidHandle
	}
	s.mu.Lock()
	if s.destroyed {
		s.mu.Unlock()
		return 0, InvalidHandle
	}
	if !s.running || s.stopping || s.generation != request.Generation {
		s.mu.Unlock()
		return 0, StaleRequest
	}
	if !s.connectOperation || s.protocol == nil {
		s.mu.Unlock()
		return 0, Unsupported
	}
	if !s.ready {
		s.mu.Unlock()
		return 0, Busy
	}
	protocol, ctx := s.protocol, s.ctx
	s.mu.Unlock()
	err := protocol.RefreshCoexistence(ctx, request.Endpoints, *request.Managed, request.Proofs...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping || s.generation != request.Generation || s.protocol != protocol {
		return 0, StaleRequest
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return 0, Cancelled
		}
		if errors.Is(err, net.ErrClosed) {
			return 0, Busy
		}
		if errors.Is(err, mihomo.ErrAmbiguous) {
			return 0, Unsupported
		}
		return 0, NetworkFailure
	}
	data, err := json.Marshal(struct {
		SchemaVersion int                      `json:"schema_version"`
		Generation    uint64                   `json:"generation,string"`
		State         corelib.CoexistenceState `json:"coexistence"`
	}{ABIVersion, request.Generation, protocol.Coexistence()})
	if err != nil || len(data) > MaxOutput {
		return 0, Limit
	}
	s.coexistence = data
	return request.Generation, OK
}

func (e *Engine) Coexistence(handle, generation uint64) ([]byte, Status) {
	if generation == 0 {
		return nil, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return nil, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, InvalidHandle
	}
	if !s.running || s.stopping || s.generation != generation {
		return nil, StaleRequest
	}
	if !s.connectOperation || s.protocol == nil {
		return nil, Unsupported
	}
	if s.coexistence == nil {
		return nil, Busy
	}
	return append([]byte(nil), s.coexistence...), OK
}
