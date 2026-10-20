package stack

import (
	"context"
	"net"
)

type Stack interface {
	DialTCP(context.Context, *net.TCPAddr) (net.Conn, error)
	DialUDP(context.Context, *net.UDPAddr) (net.Conn, error)
}
