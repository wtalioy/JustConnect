package bridge

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestProtocolPolicySwitchesProtectedFlowsBetweenOriginalAndCampus(t *testing.T) {
	g := newGateway(t)
	g.resourceIP.Store("127.0.0.1")
	e := New(RunProtocol)
	h := create(t, e)
	c := g.config(t)
	c.KeepAlive.Mode = "off"
	c.Listeners.SOCKS = freeAddress(t)
	c.Protection = &ProtectionConfig{Protected: []string{"127.0.0.0/8"}, Campus: []string{}}
	startProtocol(t, e, h, c)
	ready := next(t, e, h)
	if ready.State != "ready" {
		t.Fatal(ready)
	}
	native, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	go func() {
		for {
			conn, err := native.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, "original-network")
			conn.Close()
		}
	}()
	socks, err := proxy.SOCKS5("tcp", c.Listeners.SOCKS, nil, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	for i, campus := range []bool{false, true, false} {
		choices := []string{}
		if campus {
			choices = append(choices, "127.0.0.1")
		}
		if i != 0 {
			if applied, status := e.UpdatePolicy(h, policyInput(ready.Generation, uint64(i), []string{"127.0.0.0/8"}, choices)); applied != ready.Generation || status != OK {
				t.Fatal(applied, status)
			}
		}
		destination := native.Addr().String()
		if i < 2 {
			_, port, _ := net.SplitHostPort(destination)
			destination = net.JoinHostPort("campus.test", port)
		}
		destinations := []string{destination}
		if campus {
			_, port, _ := net.SplitHostPort(native.Addr().String())
			destinations = append(destinations, net.JoinHostPort("::ffff:127.0.0.1%1", port))
		}
		for _, target := range destinations {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			conn, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if campus {
				echo(t, conn)
			} else {
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				data := make([]byte, len("original-network"))
				if _, err := io.ReadFull(conn, data); err != nil || string(data) != "original-network" {
					t.Fatal("protected flow did not use its original network", string(data), err)
				}
			}
			conn.Close()
		}
	}
	if g.tcpCount.Load() != 2 {
		t.Fatal("protection changes did not constrain actual campus connections", g.tcpCount.Load())
	}
}
