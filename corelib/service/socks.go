package service

import (
	"context"
	"io"
	"net"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/dial"
)

type sessionResolver struct {
	ctx    context.Context
	dialer *dial.Dialer
}

func (r sessionResolver) Resolve(_ context.Context, host string) (context.Context, net.IP, error) {
	return r.dialer.Resolve(r.ctx, host)
}

func (p *Listeners) socksServer() *socks5.Server {
	return socks5.NewServer(
		socks5.WithAssociateHandle(p.handleSOCKSUDP),
		socks5.WithResolver(sessionResolver{p.ctx, p.dialer}),
		socks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
			target, err := p.dial(ctx, "tcp", request.DestAddr.String())
			if err != nil {
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
