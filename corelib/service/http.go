package service

import (
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
)

const (
	httpProxyMaxIdleConns        = 100
	httpProxyMaxIdleConnsPerHost = 10
	httpProxyMaxConnsPerHost     = 50
	httpProxyIdleConnTimeout     = 90 * time.Second
	httpProxyResponseTimeout     = 30 * time.Second
	httpProxyReadHeaderTimeout   = 10 * time.Second
	httpProxyServerIdleTimeout   = 90 * time.Second
)

// The MIT License (MIT)
//
// Copyright (c) 2016 Ian Denhardt <ian@zenhack.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

type httpTunnel struct {
	client net.Conn
	target net.Conn
}

type httpProxy struct {
	failure     func(error)
	closed      bool
	dialContext client.DialContextFunc
	client      *http.Client
	tunnelsMu   sync.Mutex
	tunnels     map[*httpTunnel]struct{}
}

func newHTTPProxy(dialer *dial.Dialer) *httpProxy {
	proxy := &httpProxy{
		dialContext: dialer.Dial,
		tunnels:     make(map[*httpTunnel]struct{}),
	}
	transport := &http.Transport{
		DialContext: proxy.dialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: httpProxyMaxIdleConns, MaxIdleConnsPerHost: httpProxyMaxIdleConnsPerHost,
		MaxConnsPerHost: httpProxyMaxConnsPerHost, IdleConnTimeout: httpProxyIdleConnTimeout,
		ResponseHeaderTimeout: httpProxyResponseTimeout, TLSHandshakeTimeout: httpProxyResponseTimeout,
	}

	proxy.client = &http.Client{
		Transport: transport,
		// We must pass redirect response to browser
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return proxy
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}

	req.RequestURI = ""

	resp, err := p.client.Do(req)
	if err != nil {

		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error() + "\n"))
		return
	}
	defer resp.Body.Close()

	hdr := w.Header()
	for k, v := range resp.Header {
		hdr[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	_, _ = io.Copy(w, resp.Body)

}

func (p *httpProxy) handleConnect(w http.ResponseWriter, req *http.Request) {

	targetConn, err := p.dialContext(req.Context(), "tcp", req.Host)
	if err != nil {

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error() + "\n"))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed cast to hijacker\n"))
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = targetConn.Close()
		return
	}

	tunnel := &httpTunnel{client: clientConn, target: targetConn}
	if !p.registerTunnel(tunnel) {
		_ = clientConn.Close()
		_ = targetConn.Close()
		return
	}
	defer p.unregisterTunnel(tunnel)
	defer clientConn.Close()
	defer targetConn.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {

		return
	}

	relayDone := make(chan error, 2)
	go relayHTTPConnect(targetConn, buffered, relayDone, p.failure)
	go relayHTTPConnect(clientConn, targetConn, relayDone, p.failure)
	// EOF ends one direction; the peer may still be preparing its response.
	if err := <-relayDone; err != nil {
		_ = clientConn.Close()
		_ = targetConn.Close()
	}
	<-relayDone
}

func relayHTTPConnect(dst io.Writer, src io.Reader, done chan<- error, fail func(error)) {
	var relayErr error
	defer func() {
		if recover() != nil {
			relayErr = errors.New("proxy relay panicked")
			if fail != nil {
				fail(relayErr)
			}
		}
		done <- relayErr
	}()
	_, relayErr = io.Copy(dst, src)
	if relayErr == nil {
		if conn, ok := dst.(interface{ CloseWrite() error }); ok {
			relayErr = conn.CloseWrite()
		}
	}
	if conn, ok := src.(interface{ CloseRead() error }); ok {
		_ = conn.CloseRead()
	}
}

func (p *httpProxy) registerTunnel(tunnel *httpTunnel) bool {
	p.tunnelsMu.Lock()
	defer p.tunnelsMu.Unlock()
	if p.closed {
		return false
	}
	p.tunnels[tunnel] = struct{}{}
	return true
}

func (p *httpProxy) unregisterTunnel(tunnel *httpTunnel) {
	p.tunnelsMu.Lock()
	delete(p.tunnels, tunnel)
	p.tunnelsMu.Unlock()
}

func (p *httpProxy) closeTunnels() {
	p.tunnelsMu.Lock()
	p.closed = true
	tunnels := make([]*httpTunnel, 0, len(p.tunnels))
	for tunnel := range p.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	p.tunnelsMu.Unlock()

	for _, tunnel := range tunnels {
		_ = tunnel.client.Close()
		_ = tunnel.target.Close()
	}
}

func (p *httpProxy) close() {
	p.closeTunnels()
	p.client.CloseIdleConnections()
}

func newHTTPServer(bindAddr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              bindAddr,
		Handler:           handler,
		ErrorLog:          stdlog.New(io.Discard, "", 0),
		ReadHeaderTimeout: httpProxyReadHeaderTimeout,
		IdleTimeout:       httpProxyServerIdleTimeout,
	}
}
