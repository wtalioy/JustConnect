package service

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestHTTPProxyClosesUpstreamResponseBody(t *testing.T) {
	body := &trackingBody{Reader: bytes.NewBufferString("response")}
	proxy := newHTTPProxy((&net.Dialer{}).DialContext)
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	proxy.ServeHTTP(recorder, req)

	if !body.closed.Load() {
		t.Fatal("upstream response body was not closed")
	}
}

func TestHTTPProxyTransportHasBoundedPool(t *testing.T) {
	proxy := newHTTPProxy((&net.Dialer{}).DialContext)
	transport, ok := proxy.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", proxy.client.Transport)
	}
	if transport.MaxIdleConns <= 0 || transport.MaxIdleConnsPerHost <= 0 {
		t.Fatalf("idle limits = global %d, per-host %d; want positive", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
	if transport.MaxConnsPerHost <= 0 {
		t.Fatalf("MaxConnsPerHost = %d, want positive", transport.MaxConnsPerHost)
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("IdleConnTimeout is not configured")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("ResponseHeaderTimeout is not configured")
	}
}

func TestHTTPServerBoundsInboundIdleConnections(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is not configured")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is not configured")
	}
}

func TestHTTPConnectClosesTargetWhenClientDisconnects(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetListener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	proxy := httptest.NewServer(newHTTPProxy((&net.Dialer{}).DialContext))
	defer proxy.Close()

	clientConn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetListener.Addr(), targetListener.Addr()); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var targetConn net.Conn
	select {
	case targetConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy did not connect to target")
	}
	defer targetConn.Close()

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close proxy client: %v", err)
	}
	if err := targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set target read deadline: %v", err)
	}
	var buf [1]byte
	if _, err := targetConn.Read(buf[:]); err == nil {
		t.Fatal("target connection remained readable after proxy client disconnected")
	} else if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
		t.Fatal("target connection was not closed after proxy client disconnected")
	}
}

func TestHTTPProxyKeepsCredentialsAndHopHeadersOnTheirOwnConnection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Request-Hop"} {
			if value := r.Header.Get(name); value != "" {
				t.Errorf("origin received %s: %q", name, value)
			}
		}
		if r.Header.Get("Authorization") != "Bearer origin-token" {
			t.Error("end-to-end authorization was removed")
		}
		w.Header().Set("Connection", "X-Response-Hop")
		w.Header().Set("X-Response-Hop", "private")
		w.Header().Set("Proxy-Authenticate", "Basic")
		w.Header().Set("X-Origin", "preserved")
		_, _ = io.WriteString(w, "response")
	}))
	defer origin.Close()
	proxy := newHTTPProxy((&net.Dialer{}).DialContext)
	defer proxy.close()
	req := httptest.NewRequest(http.MethodGet, origin.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic local-secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Connection", "X-Request-Hop")
	req.Header.Set("X-Request-Hop", "private")
	req.Header.Set("Authorization", "Bearer origin-token")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	for _, name := range []string{"Connection", "X-Response-Hop", "Proxy-Authenticate"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Errorf("client received %s: %q", name, value)
		}
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "response" || recorder.Header().Get("X-Origin") != "preserved" {
		t.Fatalf("response changed: status %d, headers %v, body %q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}
