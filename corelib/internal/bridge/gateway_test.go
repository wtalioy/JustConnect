package bridge

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
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

	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
)

// This gateway speaks the actual HTTP authentication and TCP/IP tunnel framing.
type gateway struct {
	nextService      atomic.Value
	deviceBinds      atomic.Int32
	browserURL       atomic.Value
	browserRedirects atomic.Int32
	HTTP             *httptest.Server
	node             net.Listener
	worker           sync.WaitGroup
	accepted         chan struct{}
	mu               sync.Mutex
	closed           bool
	conns            map[net.Conn]bool
	udpCount         atomic.Int32
	delay            atomic.Int64
	tcpCount         atomic.Int32
	authCount        atomic.Int32
	invalid          atomic.Bool
	pauseIP          atomic.Bool
	ipStarted        chan struct{}
	resumeCookies    atomic.Bool
	expireCookies    atomic.Bool
	authConfigFails  atomic.Bool
	invalidIP        atomic.Bool
	cacheProbes      atomic.Int32
	sessions         sync.Map
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	g := &gateway{accepted: make(chan struct{}), conns: make(map[net.Conn]bool), ipStarted: make(chan struct{}, 8)}
	g.HTTP = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/browser":
			w.Header().Set("Content-Type", "text/html")
			target, _ := g.browserURL.Load().(string)
			stylesheet := ""
			if r.URL.Query().Get("scope") == "unsafe" {
				stylesheet = fmt.Sprintf(`<link rel="stylesheet" href="%s/resource"><link rel="stylesheet" href="/browser-redirect">`, target)
			}
			fmt.Fprintf(w, `<html><head><link rel="icon" href="data:,"><link rel="stylesheet" href="/browser-style">%s</head><body><p id="fixture">browser TLS fixture</p><a id="otherOrigin" href="%s/browser">other origin</a></body></html>`, stylesheet, target)
		case "/browser-style":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `#fixture {--scope-proof: allowed;}`)
		case "/browser-redirect":
			g.browserRedirects.Add(1)
			target, _ := g.browserURL.Load().(string)
			http.Redirect(w, r, target+"/redirected-resource", http.StatusFound)
		case "/favicon.ico":
			w.WriteHeader(http.StatusNoContent)
		case "/public/manifest":
			fmt.Fprint(w, `{"code":0,"data":{}}`)
		case "/passport/v1/public/authConfig":
			if g.authConfigFails.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if g.resumeCookies.Load() {
				if cookie, err := r.Cookie("sid"); err == nil {
					g.cacheProbes.Add(1)
					if _, exists := g.sessions.Load(cookie.Value); exists && !g.expireCookies.Load() {
						fmt.Fprint(w, `{"code":0,"data":{"isLogin":1}}`)
						return
					}
				}
			}
			if g.invalid.Load() {
				fmt.Fprint(w, `{"code":10000004}`)
				return
			}
			fmt.Fprint(w, `{"code":0,"data":{"isLogin":0,"authServerInfoList":[{"authType":"auth/smsCheckCode","authName":"Fixture SMS","loginDomain":"fixture","authId":"fixture-primary","subType":"sms"}]}}`)
		case "/passport/v1/public/sendSms":
			fmt.Fprint(w, `{"code":0,"data":{}}`)
		case "/passport/v1/auth/smsCheckCode":
			var payload struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Code != "fixture-code" {
				t.Errorf("invalid SMS response")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			count := g.authCount.Add(1)
			sid := "private-gateway-sid"
			if g.resumeCookies.Load() {
				sid = fmt.Sprintf("private-gateway-sid-%d", count)
				g.sessions.Store(sid, "fixture-user")
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
			fmt.Fprint(w, `{"code":0,"data":{"ticket":"private-ticket"}}`)
		case "/passport/v1/auth/authCheck":
			service, _ := g.nextService.Load().(string)
			fmt.Fprintf(w, `{"code":0,"data":{"nextService":%q}}`, service)
		case "/passport/v1/auth/bindAuthDevice":
			if r.Method != http.MethodPost {
				t.Error("device binding is not POST")
			}
			g.deviceBinds.Add(1)
			fmt.Fprint(w, `{"code":0,"data":{}}`)
		case "/controller/v1/public/reportEnv":
			fmt.Fprint(w, `{"code":0,"data":{}}`)
		case "/passport/v1/user/onlineInfo":
			username := "fixture-user"
			if g.resumeCookies.Load() {
				if cookie, err := r.Cookie("sid"); err == nil {
					if owner, exists := g.sessions.Load(cookie.Value); exists {
						username = owner.(string)
					}
				}
			}
			fmt.Fprintf(w, `{"code":0,"data":{"username":%q}}`, username)
		case "/controller/v1/user/clientResource":
			fmt.Fprintf(w, `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"ID":"fixture-app","nodeGroupID":"fixture-group","accessModel":"L3VPN","addressList":[{"protocol":"udp","port":"1-65535","host":"192.0.2.10"},{"protocol":"tcp","port":"1-65535","host":"192.0.2.10"},{"protocol":"tcp","port":"1-65535","host":"campus.test","IP":["192.0.2.10"]}]}]}],"config":{"nodeGroupConf":{"majorNodeGroup":{"ID":"fixture-group"},"nodeGroupList":[{"ID":"fixture-group","addressInfo":[{"type":"wan","address":%q}]}]}}}}}}`, g.node.Addr().String())
		default:
			t.Errorf("unexpected gateway route %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	var err error
	g.node, err = tls.Listen("tcp", "127.0.0.1:0", g.HTTP.TLS.Clone())
	if err != nil {
		g.HTTP.Close()
		t.Fatal(err)
	}
	go func() {
		defer close(g.accepted)
		for {
			conn, err := g.node.Accept()
			if err != nil {
				return
			}
			g.mu.Lock()
			if g.closed {
				g.mu.Unlock()
				_ = conn.Close()
				continue
			}
			g.conns[conn] = true
			g.worker.Add(1)
			g.mu.Unlock()
			go func() {
				defer g.worker.Done()
				defer func() { _ = conn.Close(); g.mu.Lock(); delete(g.conns, conn); g.mu.Unlock() }()
				g.serveTunnel(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		g.mu.Lock()
		g.closed = true
		for conn := range g.conns {
			_ = conn.Close()
		}
		g.mu.Unlock()
		_ = g.node.Close()
		<-g.accepted
		g.worker.Wait()
		g.HTTP.Close()
	})
	return g
}
func (g *gateway) serveTunnel(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	} // TLS-only reachability probes.
	auth := make([]byte, int(binary.BigEndian.Uint16(header[5:7])))
	if _, err := io.ReadFull(conn, auth); err != nil {
		return
	}
	destination := make([]byte, 4)
	if _, err := io.ReadFull(conn, destination); err != nil {
		return
	}
	length := 0
	switch destination[3] {
	case 1:
		length = 6
	case 4:
		length = 18
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		length = int(size[0]) + 2
	default:
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(length)); err != nil {
		return
	}

	if header[2] != 0x81 {
		select {
		case g.ipStarted <- struct{}{}:
		default:
		}
		if g.pauseIP.Load() {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		payload := []byte(`{"code":0}`)
		if g.invalidIP.Load() {
			payload = []byte(`{"code":10000004}`)
		}
		response := append([]byte{5, 0xd0, 0x53, 0, 0, byte(len(payload))}, payload...)
		response = append(response, 5, 0, 0x7f, 1, 10, 0, 0, 2, 0, 0)
		time.Sleep(time.Duration(g.delay.Load()))
		if _, err := conn.Write(response); err == nil {
			g.serveL3(conn)
		}
		return
	}
	g.tcpCount.Add(1)
	payload := []byte(`{"code":0}`)
	if g.invalid.Load() {
		payload = []byte(`{"code":10000004,"message":"private-gateway-detail"}`)
	}
	response := append([]byte{5, 0x81, 0x53, 0, byte(len(payload) >> 8), byte(len(payload))}, payload...)
	response = append(response, 5, 0, 0, 1, 10, 0, 0, 2, 0, 80)
	time.Sleep(time.Duration(g.delay.Load()))
	if _, err := conn.Write(response); err != nil {
		return
	}
	if g.invalid.Load() {
		return
	}
	buf := make([]byte, 64<<10)
	first := true
	for {
		n, err := conn.Read(buf)
		if first && n > 0 && strings.HasPrefix(string(buf[:n]), "GET ") {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nvpn-response")
			return
		}
		first = false
		if n > 0 {
			time.Sleep(time.Duration(g.delay.Load()))
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
func (g *gateway) config(t *testing.T) Config {
	t.Helper()
	data := []byte(`{"schema_version":1,"server":{"host":"127.0.0.1","port":443},"auth":{"method":"auth/smsCheckCode","phone":"fixture-phone","domain":"fixture"}}`)
	c, status := ParseConfig(data)
	if status != OK {
		t.Fatal(status)
	}
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(g.HTTP.URL, "https://"))
	number, _ := strconv.Atoi(port)
	c.Server.Host, c.Server.Port = host, uint16(number)
	c.TLS.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.HTTP.Certificate().Raw}))
	return c
}
func configBytes(t *testing.T, c Config) []byte {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	return address
}
func next(t *testing.T, e *Engine, h uint64) event {
	t.Helper()
	for {
		data, _, status := e.Read(h, MaxOutput, 10000)
		if status != OK {
			t.Fatalf("protocol event status %d", status)
		}
		if strings.Contains(string(data), "private-") {
			t.Fatalf("secret in protocol event: %s", data)
		}
		var ev event
		if err := json.Unmarshal(data, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type != "diagnostic" {
			return ev
		}
	}
}
func authenticate(t *testing.T, e *Engine, h uint64) {
	t.Helper()
	ev := next(t, e, h)
	if ev.Type != "authentication" || ev.Challenge.Kind != "sms" {
		t.Fatalf("challenge = %+v", ev)
	}
	response, _ := json.Marshal(Response{SchemaVersion: ABIVersion, Generation: ev.Generation, RequestID: ev.RequestID, Action: "submit", Code: "fixture-code"})
	if status := e.Respond(h, response); status != OK {
		t.Fatal(status)
	}
}
func startProtocol(t *testing.T, e *Engine, h uint64, c Config) {
	t.Helper()
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	if ev := next(t, e, h); ev.State != "starting" {
		t.Fatalf("start = %+v", ev)
	}
	authenticate(t, e, h)
}
func awaitClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("socket remained open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("socket did not close")
	}
}
func echo(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte(strings.Repeat("owned-payload", 8192))
	result := make(chan error, 1)
	go func() { _, err := conn.Write(payload); result <- err }()
	received := make([]byte, len(payload))
	_, err := io.ReadFull(conn, received)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		for i := range payload {
			if payload[i] != received[i] {
				t.Fatalf("proxy payload changed at %d: got %q want %q", i, received[i:min(i+32, len(received))], payload[i:min(i+32, len(payload))])
			}
		}
	}
	_ = conn.SetDeadline(time.Time{})
}

// L3 framing and UDP checksums match the production tunnel, with an echo endpoint.
func (g *gateway) serveL3(conn net.Conn) {
	for {
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 {
			return
		}
		switch header[1] {
		case 0x13, 0x15:
			var length [2]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				return
			}
			data := make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			response := []byte{5, 0x95, 0, 0}
			if header[1] == 0x13 {
				var request struct {
					ConntrackHash uint64 `json:"conntrackHash"`
				}
				if json.Unmarshal(data, &request) != nil {
					return
				}
				payload := []byte(fmt.Sprintf(`{"code":0,"data":{"conntrackHash":%d,"connectToken":"fixture-token"}}`, request.ConntrackHash))
				response = append([]byte{5, 0x93, 0, byte(len(payload) >> 8), byte(len(payload))}, payload...)
			}
			time.Sleep(time.Duration(g.delay.Load()))
			if _, err := conn.Write(response); err != nil {
				return
			}
		case 0x14:
			var tokenLength [1]byte
			if _, err := io.ReadFull(conn, tokenLength[:]); err != nil {
				return
			}
			tokenAndCount := make([]byte, int(tokenLength[0])+3)
			if _, err := io.ReadFull(conn, tokenAndCount); err != nil {
				return
			}
			for range int(tokenAndCount[len(tokenAndCount)-1]) {
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				packet := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				ip := zctcpip.IPv4Packet(packet)
				if !ip.Valid() || ip.HeaderLen() < 20 || ip.Protocol() != zctcpip.UDP {
					return
				}
				udp := zctcpip.UDPPacket(ip.Payload())
				if !udp.Valid() || udp.Length() < 8 {
					return
				}
				source, destination := ip.SourceIP(), ip.DestinationIP()
				ip.SetSourceIP(destination)
				ip.SetDestinationIP(source)
				sourcePort, destinationPort := udp.SourcePort(), udp.DestinationPort()
				udp.SetSourcePort(destinationPort)
				udp.SetDestinationPort(sourcePort)
				udp.ResetChecksum(ip.PseudoSum())
				ip.ResetChecksum()
				time.Sleep(time.Duration(g.delay.Load()))
				response := append([]byte{5, 0x94, byte(len(packet) >> 8), byte(len(packet))}, packet...)
				if _, err := conn.Write(response); err != nil {
					return
				}
				g.udpCount.Add(1)
			}
		default:
			return
		}
	}
}
