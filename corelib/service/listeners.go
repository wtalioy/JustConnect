package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

// Listeners owns listeners, accepted and outgoing sockets, and proxy workers.
type Listeners struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dialer      *dial.Dialer
	mu          sync.Mutex
	closed      bool
	connections map[io.Closer]struct{}
	listeners   []net.Listener
	http        *http.Server
	proxy       *httpProxy
	tun         *tunIngress
	workers     sync.WaitGroup
	errors      chan error
	failOnce    sync.Once
	closeOnce   sync.Once
}

type ownedConn struct {
	net.Conn
	owner *Listeners
	once  sync.Once
	err   error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock() })
	return c.err
}

func (c *ownedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
func (c *ownedConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func joinedContext(ctx, parent context.Context) (context.Context, context.CancelFunc) {
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(parent, cancel)
	if parent.Err() != nil {
		cancel()
	}
	return child, func() { stop(); cancel() }
}

func NewListeners(ctx context.Context, socksAddr, httpAddr string, dialer *dial.Dialer, resolver *resolve.Resolver) (*Listeners, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &Listeners{ctx: ctx, cancel: cancel, dialer: dialer, connections: make(map[io.Closer]struct{}), errors: make(chan error, 1)}
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	var socksListener, httpListener net.Listener
	for _, entry := range []struct {
		address string
		target  *net.Listener
	}{{socksAddr, &socksListener}, {httpAddr, &httpListener}} {
		if entry.address == "" {
			continue
		}
		host, _, err := net.SplitHostPort(entry.address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("proxy listener must use a loopback IP address")
		}
		listener, err := net.Listen("tcp", entry.address)
		if err != nil {
			return nil, err
		}
		*entry.target = listener
		p.listeners = append(p.listeners, listener)
	}
	if socksListener != nil {
		server := p.socksServer(resolver)
		p.start(func() {
			for {
				conn, err := socksListener.Accept()
				if err != nil {
					if p.ctx.Err() == nil {
						p.fail(err)
					}
					return
				}
				owned, err := p.own(conn)
				if err != nil {
					continue
				}
				p.start(func() { defer owned.Close(); _ = server.ServeConn(owned) })
			}
		})
	}
	if httpListener != nil {
		p.proxy = newHTTPProxy(dialer)
		p.proxy.dialContext = p.dial
		p.proxy.client.Transport.(*http.Transport).DialContext = p.dial
		p.proxy.failure = p.fail
		p.http = newHTTPServer(httpAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.begin() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			defer p.workers.Done()
			defer p.recoverWorker()
			p.proxy.ServeHTTP(w, r)
		}))
		p.http.BaseContext = func(net.Listener) context.Context { return p.ctx }
		p.start(func() {
			if err := p.http.Serve(httpListener); err != nil && p.ctx.Err() == nil {
				p.fail(err)
			}
		})
	}
	success = true
	return p, nil
}

func (p *Listeners) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.workers.Add(1)
	return true
}
func (p *Listeners) recoverWorker() {
	if recover() != nil {
		p.fail(errors.New("proxy worker panicked"))
	}
}

func (p *Listeners) start(work func()) {
	if p.begin() {
		go func() { defer p.workers.Done(); defer p.recoverWorker(); work() }()
	}
}
func (p *Listeners) fail(err error)       { p.failOnce.Do(func() { p.errors <- err; p.cancel() }) }
func (p *Listeners) Errors() <-chan error { return p.errors }
func (p *Listeners) own(conn net.Conn) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	owned := &ownedConn{Conn: conn, owner: p}
	p.connections[owned] = struct{}{}
	return owned, nil
}
func (p *Listeners) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := joinedContext(ctx, p.ctx)
	defer cancel()
	conn, err := p.dialer.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return p.own(conn)
}
func (p *Listeners) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.mu.Lock()
		p.closed = true
		connections := make([]io.Closer, 0, len(p.connections))
		for conn := range p.connections {
			connections = append(connections, conn)
		}
		p.mu.Unlock()
		for _, listener := range p.listeners {
			_ = listener.Close()
		}
		if p.http != nil {
			_ = p.http.Close()
		}
		if p.proxy != nil {
			p.proxy.close()
		}
		for _, conn := range connections {
			_ = conn.Close()
		}
		if p.tun != nil {
			p.tun.close()
		}
		p.workers.Wait()
	})
}
