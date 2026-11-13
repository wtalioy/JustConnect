package corelib

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"github.com/wtalioy/JustConnect/corelib/service"
	"github.com/wtalioy/JustConnect/corelib/stack/gvisor"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

const DefaultDNSCacheTTL uint64 = 60
const DefaultSessionRefreshInterval = 5 * time.Minute
const DefaultNodeRefreshInterval = 5 * time.Minute

var ErrLocalProxyListen = errors.New("local SOCKS5 listener unavailable")

type Options struct {
	Client             atrust.ClientOptions
	Setup              atrust.SetupOptions
	Underlay           underlay.Options
	SOCKS              string
	HTTP               string
	SecondaryDNS       string
	DNSCacheTTL        uint64
	DisableRemoteDNS   bool
	DomainDNS          map[string]string
	KeepAliveMode      string
	KeepAliveURL       string
	QueryAuthMethods   bool
	LocalProxy         bool
	ProxyExportTargets []netip.AddrPort
	ProtectionPolicy   func() *policy.ProtectionPolicy
	OriginalDNS        *resolve.OriginalDNS
}

type Observer struct {
	Ready       func() error
	AuthMethods func([]auth.AuthInfo) error
	Resources   func(Resources)
}

// Resources borrows the session's parsed data read-only for the observer call.
type Resources struct {
	IPs                           []client.IPResource
	PrivateIPRanges               [][2]netip.Addr
	Domains                       client.DomainResources
	DomainDNSPermissions          client.DomainResources
	DNSRecords                    map[string][]net.IP
	CampusDNS                     string
	CampusDNSEnabled              bool
	DomainDNSNames                []string
	UnderlayInterface             string
	OriginalAuthenticationAddress netip.Addr
	Listeners                     service.ListenerAddresses
}

// Session owns one protocol invocation; the ABI serializes starts and joins Run on stop.
// An injected dialer remains owned by its caller, as in atrust.ClientOptions.
type Session struct {
	options   Options
	listeners atomic.Pointer[service.Listeners]
	upstream  atomic.Pointer[sessionUpstream]
}

// AttachTUN takes device ownership only on success; Run closes it before returning.
func (s *Session) AttachTUN(device io.ReadWriteCloser, mtu uint32, publishDNSRoutes func(context.Context, []netip.Addr, bool) error) error {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.AttachTUN(device, mtu, publishDNSRoutes)
	}
	return net.ErrClosed
}

func (s *Session) CampusDNSRecords() map[string][]string {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.CampusDNSRecords()
	}
	return nil
}

func (s *Session) OriginalDNSRecords() map[string][]string {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.OriginalDNSRecords()
	}
	return nil
}

func (s *Session) PrepareOriginalDNS(sources *resolve.OriginalDNS) error {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.PrepareOriginalDNS(sources)
	}
	return net.ErrClosed
}

func (s *Session) ReplaceSupplementalFallbacks(sources *resolve.OriginalDNS) error {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.ReplaceSupplementalFallbacks(sources)
	}
	return net.ErrClosed
}

func (s *Session) OriginalDNSListeners() map[string]string {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.OriginalDNSListeners()
	}
	return nil
}

func (s *Session) ActiveTUNAddresses() []string {
	if listeners := s.listeners.Load(); listeners != nil {
		return listeners.ActiveTUNAddresses()
	}
	return nil
}

func NewSession(options Options) *Session {
	options.Setup.ClientData = bytes.Clone(options.Setup.ClientData)
	return &Session{options: options}
}

func (s *Session) Run(parent context.Context, observer Observer) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("core_session_panicked")
		}
	}()
	ctx, cancel := context.WithCancel(parent)
	var ownedUnderlay *underlay.Dialer
	var vpn *atrust.Client
	var network *gvisor.Stack
	var resolver *resolve.Resolver
	var listeners *service.Listeners
	defer func() {
		if ownedUnderlay != nil {
			ownedUnderlay.Close()
		}
	}()
	defer func() {
		if resolver != nil {
			resolver.Close()
		}
	}()
	defer func() {
		if network != nil {
			network.Close()
		}
	}()
	defer func() {
		if listeners != nil {
			listeners.Close()
		}
	}()
	defer func() {
		if vpn != nil {
			vpn.Close()
		}
	}()
	defer cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	options := s.options
	if options.Setup.ServerAddress == "" || options.Setup.ServerPort < 1 || options.Setup.ServerPort > 65535 || options.Setup.SessionRefreshInterval < 0 || options.Setup.BestNodesRefreshInterval < 0 || options.DNSCacheTTL > uint64((1<<63-1)/int64(time.Second)) {
		return errors.New("invalid_session_options")
	}
	if err := ValidateKeepAlive(options.KeepAliveMode, options.KeepAliveURL); err != nil {
		return err
	}
	var reservedSOCKS net.Listener
	if options.LocalProxy && !options.QueryAuthMethods {
		reservedSOCKS, err = service.ListenLoopback(ctx, options.SOCKS)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLocalProxyListen, err)
		}
		defer func() {
			if reservedSOCKS != nil {
				_ = reservedSOCKS.Close()
			}
		}()
	}
	clientOptions := options.Client
	if clientOptions.UnderlayDialer == nil {
		if options.Underlay.Diagnostic == nil {
			options.Underlay.Diagnostic = clientOptions.Diagnostic
		}
		ownedUnderlay, err = underlay.New(options.Underlay)
		if err != nil {
			return fmt.Errorf("underlay_failed: %w", err)
		}
		clientOptions.UnderlayDialer = ownedUnderlay
	}
	vpn = atrust.NewClient(clientOptions)
	if options.QueryAuthMethods {
		methods, queryErr := vpn.GetAuthInfoList(ctx, options.Setup.ServerAddress, options.Setup.ServerPort)
		if queryErr != nil {
			return fmt.Errorf("auth_query_failed: %w", queryErr)
		}
		if observer.AuthMethods != nil {
			return observer.AuthMethods(methods)
		}
		return nil
	}
	if clientOptions.Diagnostic != nil {
		if clientOptions.AllowUnverifiedNodes {
			clientOptions.Diagnostic("tls_node_verification_disabled")
		}
		clientOptions.Diagnostic("authentication_started")
	}
	if options.Setup.SessionRefreshInterval == 0 {
		options.Setup.SessionRefreshInterval = DefaultSessionRefreshInterval
	}
	if options.Setup.BestNodesRefreshInterval == 0 {
		options.Setup.BestNodesRefreshInterval = DefaultNodeRefreshInterval
	}
	trafficReady := make(chan struct{})
	var probe func(context.Context) string
	options.Setup.MaintainTraffic = func(ctx context.Context) {
		select {
		case <-ctx.Done():
			return
		case <-trafficReady:
		}
		result := probe(ctx)
		if ctx.Err() == nil && clientOptions.Observe != nil {
			clientOptions.Observe("traffic", result)
		}
	}
	if _, err = vpn.SetupContext(ctx, options.Setup); err != nil {
		return fmt.Errorf("setup_failed: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	network, err = gvisor.NewStack(vpn)
	if err != nil {
		return fmt.Errorf("stack_failed: %w", err)
	}
	domains, err := vpn.DomainResources()
	if err != nil {
		return err
	}
	dnsResource, err := vpn.DNSResource()
	if err != nil {
		return err
	}
	ips, err := vpn.IPResources()
	if err != nil {
		return err
	}
	remoteDNS, _ := vpn.DNSServer()
	ttl := options.DNSCacheTTL
	if ttl == 0 {
		ttl = DefaultDNSCacheTTL
	}
	resolver = resolve.NewResolver(network, remoteDNS, options.SecondaryDNS, ttl, domains, dnsResource, !options.DisableRemoteDNS && remoteDNS != "")
	resolver.ProtectionPolicy = options.ProtectionPolicy
	resolver.OriginalDNS = options.OriginalDNS

	dialer := dial.NewDialer(network, resolver, ips, options.LocalProxy)
	dialer.ProtectionPolicy = options.ProtectionPolicy
	dialer.OriginalAuthentication = originalAuthenticationOrigin(ctx, options.Setup.LoginMethod, clientOptions.TLSConfig, clientOptions.UnderlayDialer.DialContext)
	resolver.DomainDNS = options.DomainDNS
	resolver.DomainDNSDial = dialer.DialDomainDNS
	if ownedUnderlay != nil && !options.LocalProxy {
		upstream := &sessionUpstream{source: ownedUnderlay, gate: make(chan struct{}, 1)}
		dialer.Upstream = upstream.dialer
		s.upstream.Store(upstream)
		defer s.upstream.Store(nil)
	}
	if reservedSOCKS != nil {
		listeners, err = service.StartLocalSOCKS(ctx, reservedSOCKS, dialer)
		reservedSOCKS = nil
	} else {
		listeners, err = service.NewListeners(ctx, options.SOCKS, options.HTTP, dialer, resolver)
	}
	if err != nil {
		return fmt.Errorf("listeners_failed: %w", err)
	}
	s.listeners.Store(listeners)
	defer s.listeners.Store(nil)
	if observer.Resources != nil && options.LocalProxy {
		scoped, _ := ipresource.ScopedRanges(ips)
		scoped = appendProxyExportTargets(scoped, dialer, options.ProxyExportTargets)
		observer.Resources(Resources{IPs: scoped, Domains: domains, DomainDNSPermissions: proxyExportDomainDNS(ctx, dialer, ips, options.DomainDNS),
			OriginalAuthenticationAddress: dialer.OriginalAuthentication.Address, Listeners: listeners.Addresses()})
	} else if observer.Resources != nil {
		var domainDNSNames []string
		for host := range options.DomainDNS {
			domainDNSNames = append(domainDNSNames, host)
		}
		slices.Sort(domainDNSNames)
		var interfaceName string
		if selected, ok := clientOptions.UnderlayDialer.(interface{ InterfaceName() string }); ok {
			interfaceName = selected.InterfaceName()
		}
		scopedIPs, privateRanges := dialer.CaptureIPResources()
		observer.Resources(Resources{IPs: scopedIPs, PrivateIPRanges: privateRanges, Domains: domains, DNSRecords: dnsResource,
			CampusDNS: remoteDNS, CampusDNSEnabled: !options.DisableRemoteDNS && remoteDNS != "", DomainDNSNames: domainDNSNames, UnderlayInterface: interfaceName,
			OriginalAuthenticationAddress: dialer.OriginalAuthentication.Address,
			Listeners:                     listeners.Addresses()})
	}
	var probeDNS net.IP
	if !options.DisableRemoteDNS && options.KeepAliveMode != "off" {
		probeDNS = authorizedDNS(remoteDNS, dialer)
	}
	campusProbe := dialer.CampusOnly()
	probe = func(ctx context.Context) string {
		return trafficProbe(ctx, options.KeepAliveMode, options.KeepAliveURL, probeDNS, campusProbe, resolver, clientOptions.TLSConfig)
	}
	close(trafficReady)
	if clientOptions.Observe != nil {
		result := "unknown"
		if options.KeepAliveMode == "off" {
			result = "disabled"
		} else if options.KeepAliveMode != "target" && probeDNS == nil {
			result = "unavailable"
		}
		clientOptions.Observe("traffic", result)
	}
	select {
	case err = <-vpn.Errors():
		return err
	case err = <-network.Errors():
		return fmt.Errorf("stack_failed: %w", err)
	case err = <-listeners.Errors():
		return fmt.Errorf("listeners_failed: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if clientOptions.Diagnostic != nil {
		clientOptions.Diagnostic("transport_connected")
	}
	if observer.Ready != nil {
		if err = observer.Ready(); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-vpn.Errors():
		return err
	case err = <-network.Errors():
		return fmt.Errorf("stack_failed: %w", err)
	case err = <-listeners.Errors():
		return fmt.Errorf("listeners_failed: %w", err)
	}
}
