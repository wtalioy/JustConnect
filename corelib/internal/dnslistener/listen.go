// Package dnslistener reserves one IPv4 endpoint for both DNS transports.
package dnslistener

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Bound pairing work when the other transport cannot use the selected port.
const portAttempts = 8

// Listen selects UDP first: a TCP ephemeral port may be excluded from UDP on Windows.
func Listen(ctx context.Context, address string) (net.Listener, *net.UDPConn, error) {
	return listenPair(ctx, address, net.ListenUDP)
}

func listenPair(ctx context.Context, address string, listenUDP func(string, *net.UDPAddr) (*net.UDPConn, error)) (net.Listener, *net.UDPConn, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, nil, err
	}
	if !endpoint.Addr().Is4() {
		return nil, nil, errors.New("DNS listeners require an IPv4 endpoint")
	}
	for range portAttempts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		udp, bindError := listenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
		if bindError != nil {
			return nil, nil, bindError
		}
		tcp, bindError := net.Listen("tcp4", udp.LocalAddr().String())
		if bindError == nil {
			return tcp, udp, nil
		}
		_ = udp.Close()
		err = bindError
		if endpoint.Port() != 0 {
			break
		}
	}
	return nil, nil, err
}
