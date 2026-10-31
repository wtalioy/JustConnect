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
	Available bool     `json:"available"`
	Active    bool     `json:"active"`
	TUN       bool     `json:"tun"`
	Mode      string   `json:"mode,omitempty"`
	Endpoints []string `json:"endpoints"`
}

type proxyObserver interface {
	ObserveProxy(context.Context) (mihomo.ProxyInfo, error)
}
type upstreamRoute struct {
	state CoexistenceState
	dial  client.DialContextFunc
}
type sessionUpstream struct {
	source proxyObserver
	gate   chan struct{}
	route  atomic.Pointer[upstreamRoute]
}

func (u *sessionUpstream) dialer() client.DialContextFunc {
	if current := u.route.Load(); current != nil {
		return current.dial
	}
	return nil
}

func (u *sessionUpstream) refresh(ctx context.Context, endpoints []string, managed bool) error {
	select {
	case u.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-u.gate }()
	info, err := u.source.ObserveProxy(ctx)
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
	state := CoexistenceState{Available: info.Proxy != nil, Mode: info.Mode, TUN: info.TunEnabled, Endpoints: slices.Clone(info.Endpoints)}
	if state.Endpoints == nil {
		state.Endpoints = []string{}
	}
	state.Active = info.Proxy != nil && managed || info.TunEnabled || slices.ContainsFunc(endpoints, func(endpoint string) bool { return slices.Contains(info.Endpoints, endpoint) })
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

func (s *Session) RefreshCoexistence(ctx context.Context, endpoints []string, managed bool) error {
	if current := s.upstream.Load(); current != nil {
		return current.refresh(ctx, endpoints, managed)
	}
	return net.ErrClosed
}

func (s *Session) Coexistence() CoexistenceState {
	if current := s.upstream.Load(); current != nil {
		if route := current.route.Load(); route != nil {
			state := route.state
			state.Endpoints = slices.Clone(state.Endpoints)
			return state
		}
	}
	return CoexistenceState{Endpoints: []string{}}
}
