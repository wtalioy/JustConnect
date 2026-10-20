package service

import (
	"context"
	"io"
	"net"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

type sessionResolver struct {
	ctx      context.Context
	resolver *resolve.Resolver
}

func (r sessionResolver) Resolve(_ context.Context, host string) (context.Context, net.IP, error) {
	return r.resolver.Resolve(r.ctx, host)
}

func (p *Listeners) socksServer(resolver *resolve.Resolver) *socks5.Server {
	return socks5.NewServer(
		socks5.WithAssociateHandle(p.handleSOCKSUDP),
		socks5.WithResolver(sessionResolver{p.ctx, resolver}),
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
			relayDone := make(chan struct{}, 2)
			go relayHTTPConnect(target, request.Reader, relayDone, p.fail)
			go relayHTTPConnect(writer, target, relayDone, p.fail)
			<-relayDone
			_ = target.Close()
			if closer, ok := writer.(io.Closer); ok {
				_ = closer.Close()
			}
			<-relayDone
			return nil
		}),
	)
}
