package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type localUnderlay struct{ net.Dialer }

func (*localUnderlay) ExcludeIP(net.IP) {}

func TestSetupOwnsAuthenticationLifetimeAndRollsBack(t *testing.T) {
	for _, saveFails := range []bool{false, true} {
		t.Run(fmt.Sprint(saveFails), func(t *testing.T) {
			refreshed := make(chan struct{}, 1)
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/public/manifest":
					fmt.Fprint(w, `{"code":0,"data":{}}`)
				case "/passport/v1/public/authConfig":
					fmt.Fprint(w, `{"code":0,"data":{"isLogin":1}}`)
					select {
					case refreshed <- struct{}{}:
					default:
					}
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
			var workers sync.WaitGroup
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
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
			resource := fmt.Sprintf(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"ID":"test"},"nodeGroupList":[{"ID":"test","addressInfo":[{"type":"wan","address":%q}]}]}}}}}}`, listener.Addr().String())
			host, port, _ := net.SplitHostPort(strings.TrimPrefix(gateway.URL, "https://"))
			portNumber, _ := strconv.Atoi(port)
			c := NewClient(ClientOptions{UnderlayDialer: &localUnderlay{}, Session: SessionOptions{SID: "sid", DeviceID: "device"}})
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			saveErr := errors.New("save rejected")
			options := SetupOptions{ServerAddress: host, ServerPort: portNumber, ResourceData: []byte(resource), SessionRefreshInterval: time.Millisecond}
			if saveFails {
				options.SaveClientData = func([]byte) error { return saveErr }
			}
			_, err = c.SetupContext(ctx, options)
			cancel()
			if saveFails {
				if !errors.Is(err, saveErr) {
					t.Fatalf("setup = %v", err)
				}
				select {
				case <-c.l3Tunnel.closeCh:
				default:
					t.Fatal("partial L3 initialization not rolled back")
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
