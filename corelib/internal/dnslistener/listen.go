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

// Listen starts with UDP, then alternates allocators if the other transport excludes its port.
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
	for attempt := range portAttempts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var tcp net.Listener
		var udp *net.UDPConn
		var bindError error
		if attempt%2 == 0 {
			udp, bindError = listenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
			if bindError != nil {
				return nil, nil, bindError
			}
			tcp, bindError = net.Listen("tcp4", udp.LocalAddr().String())
		} else {
			tcp, bindError = net.Listen("tcp4", endpoint.String())
			if bindError != nil {
				return nil, nil, bindError
			}
			selected := tcp.Addr().(*net.TCPAddr)
			udp, bindError = listenUDP("udp4", &net.UDPAddr{IP: selected.IP, Port: selected.Port, Zone: selected.Zone})
		}
		if bindError == nil {
			return tcp, udp, nil
		}
		if tcp != nil {
			_ = tcp.Close()
		}
		if udp != nil {
			_ = udp.Close()
		}
		err = bindError
		if endpoint.Port() != 0 {
			break
		}
	}

	return nil, nil, err
}
