package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

type localUnderlay struct{ net.Dialer }

func (*localUnderlay) ExcludeIP(net.IP) {}

func TestSetupOwnsAuthenticationLifetimeAndRollsBack(t *testing.T) {
	for _, saveFails := range []bool{false, true} {
		t.Run(fmt.Sprint(saveFails), func(t *testing.T) {
			var resource atomic.Value
			var setupCancelled atomic.Bool
			refreshed := make(chan struct{}, 1)
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/public/manifest":
					fmt.Fprint(w, `{"code":0,"data":{}}`)
				case "/passport/v1/public/authConfig":
					fmt.Fprint(w, `{"code":0,"data":{"isLogin":1}}`)
					if setupCancelled.Load() && r.URL.Query().Get("needTicket") == "0" {
						select {
						case refreshed <- struct{}{}:
						default:
						}
					}
				case "/passport/v1/user/onlineInfo":
					fmt.Fprint(w, `{"code":0,"data":{"username":"fixture-user"}}`)
				case "/controller/v1/user/clientResource":
					fmt.Fprint(w, resource.Load().(string))
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer gateway.Close()
			listener, err := tls.Listen("tcp", "127.0.0.1:0", gateway.TLS.Clone())
			if err != nil {
				t.Fatal(err)
			}
			var connections atomic.Int32
			var workers sync.WaitGroup
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					connections.Add(1)
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						header := make([]byte, 7)
						if _, err := io.ReadFull(conn, header); err != nil {
							return
						} // Probes close after TLS.
						payload := make([]byte, int(binary.BigEndian.Uint16(header[5:7]))+10)
						if _, err := io.ReadFull(conn, payload); err != nil {
							return
						}
						auth := []byte(`{"code":0}`)
						response := []byte{5, 0xd0, 0x53, 0, 0, byte(len(auth))}
						response = append(response, auth...)
						response = append(response, 5, 0, 0x7f, 1, 10, 0, 0, 2, 0, 0)
						_, _ = conn.Write(response)
					}()
				}
			}()
			defer func() { _ = listener.Close(); <-accepted; workers.Wait() }()
			resource.Store(fmt.Sprintf(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"ID":"test"},"nodeGroupList":[{"ID":"test","addressInfo":[{"type":"wan","address":%q}]}]}}}}}}`, listener.Addr().String()))
			host, port, _ := net.SplitHostPort(strings.TrimPrefix(gateway.URL, "https://"))
			portNumber, _ := strconv.Atoi(port)
			c := NewClient(ClientOptions{TLSConfig: gateway.Client().Transport.(*http.Transport).TLSClientConfig, UnderlayDialer: &localUnderlay{}, Session: SessionOptions{Username: "fixture-user"}})
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			saveErr := errors.New("save rejected")
			options := SetupOptions{ServerAddress: host, ServerPort: portNumber, SessionRefreshInterval: time.Millisecond}
			server := net.JoinHostPort(host, port)
			options.ClientData, err = json.Marshal(auth.ClientAuthData{
				Identity: cacheIdentity(options, server, "fixture-user"), DeviceID: "device",
				Cookies:           []auth.Cookie{{Host: server, Scheme: "https", Name: "sid", Value: "sid"}},
				ServerVersionInfo: json.RawMessage(`{"code":0}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			if saveFails {
				options.SaveClientData = func([]byte) error { return saveErr }
			}
			_, err = c.SetupContext(ctx, options)
			cancel()
			setupCancelled.Store(true)
			if saveFails {
				if !errors.Is(err, saveErr) {
					t.Fatalf("setup = %v", err)
				}
				if c.l3Tunnel != nil || connections.Load() != 0 {
					t.Fatal("rejected authentication persistence must fail before allocating or dialing tunnels")
				}
				c.Close()
				if _, err := c.SetupContext(context.Background(), options); !errors.Is(err, context.Canceled) {
					t.Fatalf("closed setup = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-refreshed:
			case <-time.After(time.Second):
				t.Fatal("setup cancellation killed ongoing session refresh")
			}
			c.Close()
			select {
			case <-c.refreshDone:
			default:
				t.Fatal("Close returned before refresh exited")
			}
		})
	}
}

func TestQueryCancellationReachesDialer(t *testing.T) {
	c := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.GetAuthInfoList(ctx, "vpn.example", 443)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("query = %v", err)
	}
}
