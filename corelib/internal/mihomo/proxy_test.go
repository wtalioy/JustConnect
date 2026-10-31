package mihomo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func proxyEchoTargets(t *testing.T, host string) (tcp, udp string) {
	t.Helper()
	stream, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		stream.Close()
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			conn, err := stream.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		for {
			n, peer, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = packet.WriteTo(buf[:n], peer)
		}
	}()
	t.Cleanup(func() { stream.Close(); packet.Close(); workers.Wait() })
	return stream.Addr().String(), packet.LocalAddr().String()
}

func setOwnedProxyMode(t *testing.T, c *Client, fixture *testmihomo.Fixture, mode string) {
	t.Helper()
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPatch, "http://"+fixture.Address+"/configs", strings.NewReader(`{"mode":"`+mode+`"}`))
	request.Header.Set("Authorization", "Bearer "+fixture.Secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("owned mode update failed", response.StatusCode)
	}
}

func TestOfficialProxyUsesActualListenersAndSelectedMode(t *testing.T) {
	if os.Getenv("JC_TEST_MIHOMO_BINARY") == "" {
		t.Skip("set JC_TEST_MIHOMO_BINARY for official proxy integration")
	}
	tcp, udp := proxyEchoTargets(t, "127.0.0.1")
	tcp6, udp6 := proxyEchoTargets(t, "::1")
	for _, kind := range []string{"socks-port", "mixed-port"} {
		t.Run(kind, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reserved.Addr().(*net.TCPAddr).Port
			reserved.Close()
			fixture := testmihomo.StartConfiguredBinary(t, originalControllerDNS(t), true, map[string]any{
				kind: port, "mode": "rule",
				"hosts":        map[string]string{"owned.upstream.test": "127.0.0.1"},
				"rules":        []string{"DOMAIN,owned.upstream.test,DIRECT", "IP-CIDR,127.0.0.1/32,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve", "MATCH,REJECT"},
				"proxy-groups": []any{map[string]any{"name": "GLOBAL", "type": "select", "proxies": []string{"REJECT", "DIRECT"}}},
			})
			c, err := Inspect(t.Context(), ownedProcess(t, fixture.PID))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			upstream, err := c.Proxy(t.Context())
			if err != nil || int(upstream.address.Port()) != port {
				t.Fatal("actual proxy listener was not discovered", err)
			}
			for _, mode := range []string{"rule", "global", "direct", "rule"} {
				setOwnedProxyMode(t, c, fixture, mode)
				for _, network := range []string{"tcp", "udp"} {
					for _, host := range []string{"127.0.0.1", "owned.upstream.test", "::1"} {
						address := tcp
						if network == "udp" {
							address = udp
						}
						if host == "::1" {
							address = tcp6
							if network == "udp" {
								address = udp6
							}
						}
						_, port, _ := net.SplitHostPort(address)
						address = net.JoinHostPort(host, port)
						ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
						conn, err := upstream.DialContext(ctx, network, address)
						cancel()
						if err != nil {
							if mode == "global" {
								continue
							}
							t.Fatalf("%s/%s/%s did not use the owned upstream: %v", mode, network, address, err)
						}
						conn.SetDeadline(time.Now().Add(time.Second))
						payloads := [][]byte{[]byte("owned " + network + " exit"), bytes.Repeat([]byte("x"), 16384)}
						if network == "udp" {
							packet, err := statute.NewDatagram(address, nil)
							if err != nil {
								t.Fatal(err)
							}
							if n, err := conn.Write(payloads[1]); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
								t.Fatal("oversized UDP was allowed to be silently truncated by upstream", n, err)
							}
							payloads[1] = bytes.Repeat([]byte("x"), maxProxyUDPPacket-len(packet.Header()))
							payloads = append(payloads, []byte{})
						}
						for _, payload := range payloads {
							n, writeErr := conn.Write(payload)
							buffer := make([]byte, max(1, len(payload)))
							var readErr error
							var received int
							if writeErr == nil {
								if network == "tcp" {
									received, readErr = io.ReadFull(conn, buffer[:len(payload)])
								} else {
									received, readErr = conn.Read(buffer)
								}
							}
							if mode == "global" {
								if readErr == nil && writeErr == nil {
									t.Error("GLOBAL's REJECT selection was bypassed")
								}
								break
							}
							if writeErr != nil || readErr != nil || n != len(payload) || !bytes.Equal(buffer[:received], payload) {
								conn.Close()
								t.Fatalf("%s/%s/%s payload lost: wrote=%d read=%d write=%v read=%v", mode, network, address, n, received, writeErr, readErr)
							}
						}
						conn.Close()
					}
				}
			}
			// The same port cannot be used through a recycled native process identity.
			upstream.process.Started++
			if conn, err := upstream.DialContext(t.Context(), "tcp", tcp); !errors.Is(err, ErrUnavailable) {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("reused process identity acquired proxy authority", err)
			}
			upstream.process.Started--
			conn, err := upstream.DialContext(t.Context(), "udp", udp)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			process, err := os.FindProcess(fixture.PID)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Kill(); err != nil {
				t.Fatal(err)
			}
			_, err = conn.Read(make([]byte, 1))
			conn.Close()
			if err == nil {
				t.Fatal("UDP association outlived its control connection")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("controller exit did not interrupt blocked UDP read")
			}
		})
	}
}

func TestProxyRejectsUnownedAndDisabledListeners(t *testing.T) {
	foreign, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	fixture := testmihomo.Start(t, testmihomo.Options{Transport: "ipc", SOCKSPort: foreign.Addr().(*net.TCPAddr).Port})
	c, err := Inspect(t.Context(), ownedProcess(t, fixture.PID))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Proxy(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("advertised foreign port produced a proxy", err)
	}
	// A listener's open port alone is insufficient evidence of controller ownership.
	p := &Proxy{process: c.endpoint.process, address: netip.MustParseAddrPort(foreign.Addr().String())}
	for _, network := range []string{"tcp", "udp"} {
		if conn, err := p.DialContext(t.Context(), network, "127.0.0.1:443"); !errors.Is(err, ErrUnavailable) {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("foreign listener received proxy authority", err)
		}
	}
	// An owned port with the wrong protocol must still be cancellable during negotiation.
	p.address = netip.MustParseAddrPort(fixture.Address)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if conn, err := p.DialContext(ctx, "udp", "127.0.0.1:443"); !errors.Is(err, context.DeadlineExceeded) {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("stalled proxy handshake ignored cancellation", err)
	}
}
