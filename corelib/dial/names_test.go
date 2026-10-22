package dial

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

func TestProtectedHostRetainsNativeTCPAndResolvedSOCKSContext(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("native"))
			conn.Close()
		}
	}()
	p, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "exact", Value: "localhost"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := &p
	s := &capturingStack{}
	r := resolve.NewResolver(nil, "", "", 60, client.DomainResources{"localhost": {{Protocol: "tcp", PortMin: 1, PortMax: 65535}}},
		map[string][]net.IP{"localhost": {net.IPv4(127, 0, 0, 2)}}, false)
	defer r.Close()
	r.ProtectionPolicy = func() *policy.ProtectionPolicy { return current }
	d := NewDialer(s, r, []client.IPResource{{IPMin: net.IPv4(127, 0, 0, 1), IPMax: net.IPv4(127, 0, 0, 255), PortMin: 1, PortMax: 65535, Protocol: "all"}}, false)
	d.ProtectionPolicy = func() *policy.ProtectionPolicy { return current }
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	var resolvedCtx context.Context
	for _, resolved := range []bool{false, true} {
		var conn net.Conn
		if resolved {
			// SOCKS resolves the name before invoking the common IP dialer.
			next, _, err := r.Resolve(ctx, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			resolvedCtx = next
			conn, err = d.DialIPPort(next, "tcp", net.JoinHostPort("127.0.0.1", port))
			if err != nil {
				t.Fatal(err)
			}
		} else {
			conn, err = d.Dial(ctx, "tcp", "localhost:"+port)
			if err != nil {
				t.Fatal(err)
			}
		}
		if conn == nil {
			t.Fatal("protected name entered the campus stack")
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		data := make([]byte, 6)
		n, err := conn.Read(data)
		conn.Close()
		if err != nil || string(data[:n]) != "native" {
			t.Fatal("native server not reached", err)
		}
	}
	if s.tcpCalls != 0 {
		t.Fatal("native hostname was captured by a campus IP grant")
	}
	d.alwaysUseVPN = true
	if _, err := d.Dial(ctx, "tcp", "localhost:"+port); !errors.Is(err, policy.ErrProtectedTarget) {
		t.Fatal("forced campus lookup escaped", err)
	}
	next, err := policy.NewProtectionPolicy([]string{"127.0.0.0/8"}, nil, []policy.NameRule{{Kind: "exact", Value: "localhost"}}, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	current = &next
	d.alwaysUseVPN = false
	old, err := d.DialIPPort(resolvedCtx, "tcp", listener.Addr().String())
	if err != nil || old == nil || s.tcpCalls != 0 {
		t.Fatal("policy update changed an already resolved flow", err)
	}
	old.Close()
	if _, err := d.Dial(ctx, "tcp", "localhost:"+port); err != nil || s.tcpCalls != 1 {
		t.Fatal("exact name choice did not reach authorized campus resource", err)
	}
	conn, err := d.DialIPPort(ctx, "tcp", listener.Addr().String())
	if err != nil || conn == nil || s.tcpCalls != 1 {
		t.Fatal("name exception also captured direct IP traffic", err)
	}
	conn.Close()
	d.ipResources, d.resourceIndex = nil, nil
	r2 := resolve.NewResolver(nil, "", "", 60, nil, map[string][]net.IP{"localhost": {net.IPv4(127, 0, 0, 2)}}, false)
	defer r2.Close()
	r2.ProtectionPolicy = r.ProtectionPolicy
	d.resolver = r2
	if _, err := d.Dial(ctx, "tcp", "localhost:"+port); !errors.Is(err, ErrACLDenied) {
		t.Fatal("name choice granted authorization or fell back", err)
	}
	d.resolver = nil
	if _, err := d.Dial(ctx, "tcp", "localhost:"+port); !errors.Is(err, ErrACLDenied) {
		t.Fatal("missing resolver escaped exact campus choice", err)
	}
}
