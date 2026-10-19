package stack

import (
	"context"
	"net"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ippool"
	"github.com/wtalioy/JustConnect/corelib/internal/zcdns"
)

type Stack interface {
	Run()
	SetupResolve(r zcdns.LocalServer)
	SetupIPPool(ipPool *ippool.IPPool[[]client.DomainResource])
	DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error)
	DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error)
}
