package resolve

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"

	"github.com/patrickmn/go-cache"
	"github.com/wtalioy/JustConnect/corelib/stack"
)

type Resolver struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	domainIndex       *domainResourceIndex
	dnsResource       map[string][]net.IP
	dnsResourceCursor sync.Map
	useRemoteDNS      bool

	dnsCache *cache.Cache

	preferTCPUntil time.Time
	useTCP         bool
	// check to use tcp resolver or udp resolver
	tcpLock           sync.RWMutex
	resolutionMu      sync.Mutex
	resolutions       map[string]*sharedResolution
	resolutionClosed  bool
	activeResolutions atomic.Int64

	workers   sync.WaitGroup
	cacheMu   sync.Mutex
	closeOnce sync.Once
}

const remoteDNSTCPFallbackDelay = 300 * time.Millisecond

type lookupIPFunc func(context.Context, string, string) ([]net.IP, error)

type dnsLookupResult struct {
	ips []net.IP
	err error
}

type sharedResolution struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	waiters int
	ip      net.IP
	err     error
}

type contextKey string

var (
	ContextKeyResolveHost    = contextKey("RESOLVE_HOST")
	ContextKeyDomainResource = contextKey("DOMAIN_RESOURCE")
	ContextKeyIPResource     = contextKey("IP_RESOURCE")
)

func TCPPrefersL3(ctx context.Context) bool {
	if resource, ok := ctx.Value(ContextKeyDomainResource).(client.DomainResource); ok {
		return resource.EnableTCPPrefL3
	}
	if resource, ok := ctx.Value(ContextKeyIPResource).(client.IPResource); ok {
		return resource.EnableTCPPrefL3
	}
	return false
}

// Resolve ip address. If the host could be visited via VPN, this function set a DOMAIN_RESOURCE value in context. If resolve success, this function set a RESOLVE_HOST value in context.
func (r *Resolver) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	return r.resolve(ctx, host, false, true)
}

var ErrCampusDNSUnavailable = errors.New("campus DNS unavailable")

// ResolveCampus excludes public fallback and shared cache entries of unknown origin.
func (r *Resolver) ResolveCampus(ctx context.Context, host string, allowDNS bool) (context.Context, net.IP, error) {
	return r.resolve(ctx, host, true, allowDNS)
}

func (r *Resolver) resolve(ctx context.Context, host string, campusOnly, allowDNS bool) (resCtx context.Context, resIP net.IP, resErr error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	r.resolutionMu.Lock()
	closed := r.resolutionClosed
	r.resolutionMu.Unlock()
	if closed {
		return ctx, nil, net.ErrClosed
	}
	host = normalizeHostname(host)
	defer func() {
		if resErr == nil {
			resCtx = context.WithValue(resCtx, ContextKeyResolveHost, host)
		}
	}()
	if _, resources, found := matchDomainResource(r.domainIndex, host); found {
		ctx = context.WithValue(ctx, ContextKeyDomainResource, resources)
		campusOnly = true
	}

	if cachedIP, found := r.getDNSCache(host); found && !campusOnly {

		return ctx, cachedIP, nil
	}

	if r.dnsResource != nil {
		if ips, found := r.dnsResource[host]; found && len(ips) > 0 {
			cursorValue, _ := r.dnsResourceCursor.LoadOrStore(host, &atomic.Uint64{})
			cursor := cursorValue.(*atomic.Uint64)
			ip := ips[(cursor.Add(1)-1)%uint64(len(ips))]

			return ctx, ip, nil
		}

	}

	if r.useRemoteDNS && (!campusOnly || allowDNS) {
		ip, err := r.resolveCoordinated(ctx, host, func(lookupCtx context.Context) (net.IP, error) {
			return r.resolveRemote(lookupCtx, host)
		})
		if err != nil {
			if campusOnly {
				return ctx, nil, err
			}
			if ctx.Err() != nil {
				return ctx, nil, ctx.Err()
			}

			return r.ResolveWithSecondaryDNS(ctx, host)
		}

		return ctx, ip, nil
	} else {
		if campusOnly {
			return ctx, nil, ErrCampusDNSUnavailable
		}
		return r.ResolveWithSecondaryDNS(ctx, host)
	}
}

func (r *Resolver) resolveCoordinated(ctx context.Context, host string, lookup func(context.Context) (net.IP, error)) (net.IP, error) {
	r.resolutionMu.Lock()
	if r.resolutionClosed {
		r.resolutionMu.Unlock()
		return nil, net.ErrClosed
	}
	call := r.resolutions[host]
	if call == nil {
		lookupCtx, cancel := context.WithCancel(context.Background())
		call = &sharedResolution{ctx: lookupCtx, cancel: cancel, done: make(chan struct{})}
		if r.resolutions == nil {
			r.resolutions = make(map[string]*sharedResolution)
		}
		r.resolutions[host] = call
		r.activeResolutions.Add(1)
		r.workers.Add(1)
		go r.runResolution(host, call, lookup)
	}
	call.waiters++
	r.resolutionMu.Unlock()

	select {
	case <-ctx.Done():
		r.releaseResolutionWaiter(host, call)
		return nil, ctx.Err()
	case <-call.done:
		return call.ip, call.err
	}
}

func (r *Resolver) runResolution(host string, call *sharedResolution, lookup func(context.Context) (net.IP, error)) {
	defer r.workers.Done()
	defer func() {
		if recover() != nil {
			call.err = errors.New("DNS worker panicked")
		}
		r.resolutionMu.Lock()
		if r.resolutions[host] == call {
			delete(r.resolutions, host)
		}
		r.resolutionMu.Unlock()
		call.cancel()
		r.activeResolutions.Add(-1)
		close(call.done)
	}()
	call.ip, call.err = lookup(call.ctx)
}

func (r *Resolver) releaseResolutionWaiter(host string, call *sharedResolution) {
	r.resolutionMu.Lock()
	if r.resolutions[host] == call {
		call.waiters--
		if call.waiters == 0 {
			delete(r.resolutions, host)
			call.cancel()
		}
	}
	r.resolutionMu.Unlock()
}

func matchDomainResource(index *domainResourceIndex, host string) (string, []client.DomainResource, bool) {
	return index.Match(host)
}

func (r *Resolver) resolveRemote(ctx context.Context, host string) (net.IP, error) {
	r.tcpLock.RLock()
	useTCP := r.useTCP || time.Now().Before(r.preferTCPUntil)
	r.tcpLock.RUnlock()

	if useTCP {
		ips, err := r.remoteTCPResolver.LookupIP(ctx, "ip4", host)
		return r.cacheFirstIP(host, ips, err)
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(
		ctx,
		host,
		r.remoteUDPResolver.LookupIP,
		r.remoteTCPResolver.LookupIP,
		remoteDNSTCPFallbackDelay,
	)
	if err != nil {
		return nil, err
	}
	if udpFailed {
		r.preferTCPTemporarily()
	}
	return r.cacheFirstIP(host, ips, nil)
}

func lookupIPWithTCPFallback(ctx context.Context, host string, udpLookup, tcpLookup lookupIPFunc, fallbackDelay time.Duration) ([]net.IP, bool, error) {
	lookupCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	launch := func(lookup lookupIPFunc, result chan dnsLookupResult) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var answer dnsLookupResult
			defer func() {
				if recover() != nil {
					answer.err = errors.New("DNS lookup panicked")
				}
				result <- answer
			}()
			answer.ips, answer.err = lookup(lookupCtx, "ip4", host)
		}()
	}
	udpResult := make(chan dnsLookupResult, 1)
	launch(udpLookup, udpResult)

	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var tcpResult chan dnsLookupResult
	var udpErr, tcpErr error
	udpDone := false
	tcpDone := false

	startTCP := func() {
		if tcpResult != nil {
			return
		}
		tcpResult = make(chan dnsLookupResult, 1)
		launch(tcpLookup, tcpResult)
	}

	for {
		select {
		case result := <-udpResult:
			udpDone = true
			if result.err == nil {
				return result.ips, false, nil
			}
			udpErr = result.err
			startTCP()
			if tcpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case result := <-tcpResult:
			tcpDone = true
			if result.err == nil {
				return result.ips, udpDone, nil
			}
			tcpErr = result.err
			if udpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case <-timer.C:
			startTCP()
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (r *Resolver) preferTCPTemporarily() {
	r.tcpLock.Lock()
	r.preferTCPUntil = time.Now().Add(10 * time.Minute)
	r.tcpLock.Unlock()
}

func (r *Resolver) cacheFirstIP(host string, ips []net.IP, err error) (net.IP, error) {
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS lookup returned no addresses")
	}
	r.setDNSCache(host, ips[0])
	return ips[0], nil
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func (r *Resolver) ResolveWithSecondaryDNS(ctx context.Context, host string) (context.Context, net.IP, error) {
	ip, err := r.resolveCoordinated(ctx, "secondary:"+host, func(ctx context.Context) (net.IP, error) {
		targets, err := r.secondaryResolver.LookupIP(ctx, "ip4", host)
		if err != nil && ctx.Err() == nil {
			targets, err = r.secondaryResolver.LookupIP(ctx, "ip6", host)
		}
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			return nil, errors.New("DNS lookup returned no addresses")
		}
		return targets[0], nil
	})
	return ctx, ip, err
}

func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		r.resolutionMu.Lock()
		r.resolutionClosed = true
		for host, call := range r.resolutions {
			delete(r.resolutions, host)
			call.cancel()
		}
		r.resolutionMu.Unlock()
		r.workers.Wait()
	})
}

func NewResolver(stack stack.Stack, remoteDNSServer, secondaryDNSServer string, ttl uint64, domainResources client.DomainResources, dnsResource map[string][]net.IP, useRemoteDNS bool) *Resolver {
	resolver := &Resolver{
		remoteUDPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialUDP(ctx, &net.UDPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		remoteTCPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialTCP(ctx, &net.TCPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		domainIndex:  newDomainResourceIndex(domainResources),
		dnsResource:  dnsResource,
		dnsCache:     cache.New(time.Duration(ttl)*time.Second, 0),
		useRemoteDNS: useRemoteDNS,
	}

	if secondaryDNSServer != "" {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(secondaryDNSServer, "53"))
			},
		}
	} else {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}
	return resolver
}
