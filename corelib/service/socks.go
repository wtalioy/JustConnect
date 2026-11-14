package service

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

func (p *Listeners) Resolve(_ context.Context, host string) (context.Context, net.IP, error) {
	ctx, ip, err := p.dialer.Resolve(p.ctx, host)
	if err != nil && p.diagnostic != nil && p.ctx.Err() == nil {
		p.diagnostic("socks_dns_failed")
	}
	return ctx, ip, err
}

func (p *Listeners) socksServer() *socks5.Server {
	return socks5.NewServer(
		socks5.WithAssociateHandle(func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
			return p.handleSOCKSUDP(ctx, writer, request, udpIdleTimeout)
		}),
		socks5.WithResolver(p),
		socks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
			target, err := p.dial(ctx, "tcp", request.DestAddr.String())
			if err != nil {
				if p.diagnostic != nil && p.ctx.Err() == nil {
					code := "socks_campus_dial_failed"
					switch {
					case errors.Is(err, dial.ErrACLDenied), errors.Is(err, policy.ErrProtectedTarget), errors.Is(err, client.ErrResourceNotFound):
						code = "socks_destination_denied"
					case errors.Is(err, client.ErrTCPNodeConnect):
						code = "socks_tunnel_node_unreachable"
					}
					p.diagnostic(code)
				}
				_ = socks5.SendReply(writer, statute.RepHostUnreachable, nil)
				return err
			}
			defer target.Close()
			if err := socks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
				return err
			}
			relayStream(writer, request.Reader, target, p.fail)
			return nil
		}),
	)
}
