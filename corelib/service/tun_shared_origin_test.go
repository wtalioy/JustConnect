package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestTUNCampusSharesAuthenticationAddress(t *testing.T) {
	for _, pretend := range []bool{false, true} {
		name := "resolved-address"
		if pretend {
			name = "gateway-resolves-name"
		}
		t.Run(name, func(t *testing.T) { testSharedAuthenticationAddress(t, pretend) })
	}
}

func testSharedAuthenticationAddress(t *testing.T, pretend bool) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Error("relay lost the original TLS name", r.Host, r.TLS.ServerName)
		}
		io.WriteString(w, "campus-course")
	}))
	t.Cleanup(server.Close)
	shared := netip.MustParseAddr("192.0.2.7")
	campus := newDomainTunnel(t, server, pretend)
	resources := client.DomainResources{
		"example.com": {{Protocol: "tcp", PortMin: 443, PortMax: 443, AppID: "course", AddrPretend: pretend}},
		"login.test":  {{Protocol: "tcp", PortMin: 443, PortMax: 443, AppID: "authentication"}},
	}
	r := resolve.NewResolver(campus, "", "", 60, resources, map[string][]net.IP{
		"example.com": {net.IP(shared.AsSlice())}, "login.test": {net.IP(shared.AsSlice())},
	}, false)
	t.Cleanup(r.Close)
	var protection atomic.Pointer[policy.ProtectionPolicy]
	r.ProtectionPolicy = protection.Load
	d := dial.NewDialer(campus, r, nil, false)
	d.ProtectionPolicy = protection.Load
	d.OriginalAuthentication = dial.AuthenticationOrigin{Name: "login.test", Address: shared}
	ordinary := errors.New("original network selected")
	d.Upstream = func() client.DialContextFunc {
		return func(context.Context, string, string) (net.Conn, error) { return nil, ordinary }
	}
	p, err := NewListeners(t.Context(), "", "", d, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	device := &dnsPacketDevice{newPacketDevice()}
	if err := p.AttachTUN(device, 1400, nil); err != nil {
		t.Fatal(err)
	}
	peer := tunPeer(t, device.packetDevice)
	local, ownedPeer := device.TUNAddresses()
	flow := stack.TransportEndpointID{LocalAddress: tcpip.AddrFromSlice(ownedPeer.AsSlice()), RemoteAddress: tcpip.AddrFromSlice(local.AsSlice()), LocalPort: 443}
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("private peer forwarded without a live DNS binding")
	}
	query := func(host string) *dns.Msg {
		t.Helper()
		reply, err := p.tun.exchangeDNS(new(dns.Msg).SetQuestion(host+".", dns.TypeA), "udp")
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if got := query("login.test").Answer[0].(*dns.A).A.String(); got != shared.String() {
		t.Fatal("authentication address was aliased", got)
	}
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("authentication binding granted a campus alias")
	}
	if got := query("example.com").Answer[0].(*dns.A).A.String(); got != ownedPeer.String() {
		t.Fatal("shared campus name did not use the private peer", got)
	}
	if got := r.CampusDNSRecords()["example.com"]; len(got) != 1 || got[0] != shared.String() {
		t.Fatal("alias replaced the actual authorization binding", got)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, mode := range []string{"transparent", "named"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var conn net.Conn
			var err error
			if mode == "transparent" {
				conn, err = gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: flow.LocalAddress, Port: 443}, ipv4.ProtocolNumber)
			} else {
				conn, err = d.Dial(ctx, "tcp", "example.com:443")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			secure.SetDeadline(deadline)
			io.WriteString(secure, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(secure), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "campus-course" {
				t.Fatal("shared campus TLS relay failed", string(body), err)
			}
			want := "example.com:443|192.0.2.7"
			if pretend {
				want = "example.com:443|"
			}
			if called := <-campus.called; called != want {
				t.Fatal("alias reached the wrong destination", called)
			}
		})
	}
	auth := context.WithValue(t.Context(), resolve.ContextKeyResolveHost, "login.test")
	auth = context.WithValue(auth, resolve.ContextKeyDomainResource, resources["login.test"])
	if _, err := d.DialIPPort(auth, "tcp", "192.0.2.7:443"); !errors.Is(err, ordinary) {
		t.Fatal("authentication left the original network", err)
	}
	flow.LocalPort = 444
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("alias expanded campus port authorization")
	}
	flow.LocalPort = 443
	flow.RemoteAddress = tcpip.AddrFrom4([4]byte{198, 18, 0, 9})
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("foreign source reached the private alias")
	}
	blocked, err := policy.NewProtectionPolicy(nil, nil, []policy.NameRule{{Kind: "exact", Value: "example.com"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	protection.Store(&blocked)
	flow.RemoteAddress = tcpip.AddrFromSlice(local.AsSlice())
	if _, err := p.tun.dial("tcp", flow); err == nil {
		t.Fatal("withdrawn campus name retained its private alias")
	}
}

// The real aTrust client must send the bound name, not just preserve browser SNI.
type domainTunnel struct {
	*atrust.Client
	called chan string
}

func (*domainTunnel) DialUDP(context.Context, *net.UDPAddr) (net.Conn, error) {
	return nil, dial.ErrACLDenied
}

type tunnelUnderlay struct{ net.Dialer }

func (*tunnelUnderlay) ExcludeIP(net.IP) {}

func newDomainTunnel(t *testing.T, backend *httptest.Server, pretend bool) *domainTunnel {
	t.Helper()
	node, err := tls.Listen("tcp", "127.0.0.1:0", backend.TLS)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	c := atrust.NewClient(atrust.ClientOptions{
		Session:        atrust.SessionOptions{SID: "owned-session", SignKey: "00112233"},
		UnderlayDialer: &tunnelUnderlay{}, TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	})
	c.MajorNodeGroup, c.BestNodes = "owned-node", map[string]string{"owned-node": node.Addr().String()}
	campus := &domainTunnel{Client: c, called: make(chan string, 2)}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := node.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var header [7]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					t.Error(err)
					return
				}
				payload := make([]byte, binary.BigEndian.Uint16(header[5:]))
				if _, err := io.ReadFull(conn, payload); err != nil {
					t.Error(err)
					return
				}
				var request struct {
					AppID    string `json:"appId"`
					URL      string `json:"url"`
					DestAddr string `json:"destAddr"`
					DestIP   string `json:"destIP"`
				}
				if err := json.Unmarshal(payload, &request); err != nil {
					t.Error(err)
					return
				}
				wantIP := "192.0.2.7"
				if pretend {
					wantIP = ""
				}
				if request.AppID != "course" || request.URL != "tcp://example.com:443" || request.DestAddr != "example.com:443" || request.DestIP != wantIP {
					t.Errorf("aTrust lost the named grant: %+v", request)
					return
				}
				var connect [4]byte
				if _, err := io.ReadFull(conn, connect[:]); err != nil {
					t.Error(err)
					return
				}
				length := 4
				if pretend {
					var size [1]byte
					if connect[3] != 3 {
						t.Error("aTrust did not send the resource name")
						return
					}
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						t.Error(err)
						return
					}
					length = int(size[0])
				}
				destination := make([]byte, length+2)
				if _, err := io.ReadFull(conn, destination); err != nil {
					t.Error(err)
					return
				}
				wantHost := string([]byte{192, 0, 2, 7})
				if pretend {
					wantHost = "example.com"
				}
				if string(destination[:length]) != wantHost || binary.BigEndian.Uint16(destination[length:]) != 443 {
					t.Error("aTrust connected to the wrong destination")
					return
				}
				campus.called <- request.DestAddr + "|" + request.DestIP
				payload = []byte(`{"code":0}`)
				response := append([]byte{5, 0x81, 0x53, 0, 0, byte(len(payload))}, payload...)
				response = append(response, 5, 0, 0, 1, 127, 0, 0, 1, 0, 0)
				if _, err := conn.Write(response); err != nil {
					t.Error(err)
					return
				}
				target, err := net.DialTimeout("tcp", backend.Listener.Addr().String(), time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer target.Close()
				target.SetDeadline(time.Now().Add(5 * time.Second))
				done := make(chan struct{})
				go func() { io.Copy(target, conn); target.Close(); close(done) }()
				io.Copy(conn, target)
				conn.Close()
				<-done
			})
		}
	})
	t.Cleanup(func() { c.Close(); node.Close(); workers.Wait() })
	return campus
}
