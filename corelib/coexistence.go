package corelib

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
)

type CoexistenceState struct {
	Available       bool                    `json:"available"`
	Active          bool                    `json:"active"`
	TUN             bool                    `json:"tun"`
	Mode            string                  `json:"mode,omitempty"`
	Endpoints       []string                `json:"endpoints"`
	ListenerRequest *mihomo.ListenerRequest `json:"listener_request,omitempty"`
}

type proxyObserver interface {
	ObserveProxy(context.Context, []mihomo.ListenerProof) (mihomo.ProxyInfo, error)
}

func (s *Session) ObserveNetwork(ctx context.Context) (mihomo.ControllerNetwork, error) {
	if current := s.upstream.Load(); current != nil {
		if source, okay := current.source.(interface {
			ObserveNetwork(context.Context) (mihomo.ControllerNetwork, error)
		}); okay {
			return source.ObserveNetwork(ctx)
		}
	}
	return mihomo.ControllerNetwork{}, net.ErrClosed
}

type upstreamRoute struct {
	state CoexistenceState
	dial  client.DialContextFunc
}
type sessionUpstream struct {
	source proxyObserver
	gate   chan struct{}
	route  atomic.Pointer[upstreamRoute]
	proofs []mihomo.ListenerProof
}

func (u *sessionUpstream) dialer() client.DialContextFunc {
	if current := u.route.Load(); current != nil {
		return current.dial
	}
	return nil
}

func (u *sessionUpstream) refresh(ctx context.Context, endpoints []string, managed bool, proofs []mihomo.ListenerProof) error {
	select {
	case u.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-u.gate }()
	if proofs != nil {
		u.proofs = slices.Clone(proofs)
	}
	info, err := u.source.ObserveProxy(ctx, u.proofs)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		u.route.Store(&upstreamRoute{state: CoexistenceState{Endpoints: []string{}}})
		if errors.Is(err, mihomo.ErrUnavailable) {
			return nil
		}
		return err
	}
	state := CoexistenceState{Available: info.Proxy != nil, Mode: info.Mode, TUN: info.TunEnabled, ListenerRequest: info.ListenerRequest, Endpoints: slices.Clone(info.Endpoints)}
	if state.Endpoints == nil {
		state.Endpoints = []string{}
	}
	state.Active = info.Proxy != nil && managed || info.TunEnabled || slices.ContainsFunc(endpoints, func(endpoint string) bool { return slices.Contains(info.Endpoints, endpoint) })
	if info.ListenerRequest != nil && info.Proxy == nil {
		state.Active = false
		route := &upstreamRoute{state: state, dial: func(context.Context, string, string) (net.Conn, error) { return nil, mihomo.ErrUnavailable }}
		if previous := u.route.Load(); previous != nil && previous.dial != nil {
			route.dial = previous.dial
		}
		u.route.Store(route)
		return nil
	}
	if state.Active && info.Proxy == nil {
		state.Active = false
		u.route.Store(&upstreamRoute{state: state})
		return mihomo.ErrUnavailable
	}
	current := &upstreamRoute{state: state}
	if state.Active {
		current.dial = info.Proxy.DialContext
	}
	u.route.Store(current)
	return nil
}

func (s *Session) RefreshCoexistence(ctx context.Context, endpoints []string, managed bool, proofs ...mihomo.ListenerProof) error {
	if current := s.upstream.Load(); current != nil {
		return current.refresh(ctx, endpoints, managed, proofs)
	}
	return net.ErrClosed
}

func (s *Session) Coexistence() CoexistenceState {
	if current := s.upstream.Load(); current != nil {
		if route := current.route.Load(); route != nil {
			state := route.state
			state.Endpoints = slices.Clone(state.Endpoints)
			if state.ListenerRequest != nil {
				request := *state.ListenerRequest
				request.Endpoints = slices.Clone(request.Endpoints)
				state.ListenerRequest = &request
			}
			return state
		}
	}
	return CoexistenceState{Endpoints: []string{}}
}
