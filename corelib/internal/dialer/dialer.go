package dialer

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// Dialer creates network connections bound to a specific platform interface.
// It contains no interface selection or retry policy.
type Dialer struct {
	InterfaceName string
	Resolver      *net.Resolver
	// Control connections to localhost stay local after hostname resolution.
	UnboundLoopback bool
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	netDialer := &net.Dialer{}
	if d != nil {
		netDialer.Resolver = d.Resolver
		if d.InterfaceName != "" {
			if err := bindInterface(netDialer, d.InterfaceName); err != nil {
				return nil, fmt.Errorf("bind interface %q: %w", d.InterfaceName, err)
			}
			if d.UnboundLoopback {
				control := netDialer.ControlContext
				netDialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err == nil {
						if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
							return nil
						}
					}
					return control(ctx, network, address, raw)
				}
			}
		}
	}
	return netDialer.DialContext(ctx, network, address)
}
