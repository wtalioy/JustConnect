package mihomo

import (
	"context"
	"net/netip"
)

type ControllerNetwork struct {
	Device       string
	NetworkAdmin bool
}

func (c *Client) ObserveNetwork(ctx context.Context) (ControllerNetwork, error) {
	state, err := c.ReadState(ctx)
	if err != nil {
		return ControllerNetwork{}, err
	}
	if !state.TunEnabled || !c.Alive() {
		return ControllerNetwork{}, nil
	}
	return ControllerNetwork{Device: state.TunDevice, NetworkAdmin: c.endpoint.process.NetworkAdmin}, nil
}

// RuntimeState contains observed control facts, not a complete reloadable configuration.
type RuntimeState struct {
	Mode                           string
	HTTPPort, SOCKSPort, MixedPort uint16
	TunEnabled                     bool
	TunDevice, OutboundInterface   string
	RouteExcludes                  []netip.Prefix
}

func (c *Client) ReadState(ctx context.Context) (RuntimeState, error) {
	var config struct {
		Mode      *string `json:"mode"`
		HTTP      *int    `json:"port"`
		SOCKS     *int    `json:"socks-port"`
		Mixed     *int    `json:"mixed-port"`
		Interface *string `json:"interface-name"`
		Tun       *struct {
			Enable   *bool
			Device   string
			Excludes []netip.Prefix `json:"route-exclude-address"`
		}
	}
	if err := c.read(ctx, "/configs", nil, &config); err != nil {
		return RuntimeState{}, err
	}
	if config.Mode == nil || config.Interface == nil || config.Tun == nil || config.Tun.Enable == nil {
		return RuntimeState{}, ErrUnavailable
	}
	if *config.Tun.Enable && config.Tun.Device == "" {
		return RuntimeState{}, ErrUnavailable
	}
	switch *config.Mode {
	case "rule", "global", "direct":
	default:
		return RuntimeState{}, ErrUnavailable
	}
	for _, port := range []*int{config.HTTP, config.SOCKS, config.Mixed} {
		if port == nil || *port < 0 || *port > 65535 {
			return RuntimeState{}, ErrUnavailable
		}
	}
	for _, prefix := range config.Tun.Excludes {
		if !prefix.IsValid() {
			return RuntimeState{}, ErrUnavailable
		}
	}
	return RuntimeState{Mode: *config.Mode, HTTPPort: uint16(*config.HTTP), SOCKSPort: uint16(*config.SOCKS), MixedPort: uint16(*config.Mixed),
		TunEnabled: *config.Tun.Enable, TunDevice: config.Tun.Device, OutboundInterface: *config.Interface,
		RouteExcludes: config.Tun.Excludes}, nil
}
