package corelib

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/keylog"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"github.com/wtalioy/JustConnect/corelib/service"
	"github.com/wtalioy/JustConnect/corelib/stack/gvisor"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

const DefaultDNSCacheTTL uint64 = 60
const DefaultSessionRefreshInterval = 5 * time.Minute
const DefaultNodeRefreshInterval = 5 * time.Minute

type Options struct {
	Client           atrust.ClientOptions
	Setup            atrust.SetupOptions
	Underlay         underlay.Options
	TLSKeyLogFile    string
	SOCKS            string
	HTTP             string
	SecondaryDNS     string
	DNSCacheTTL      uint64
	DisableRemoteDNS bool
	QueryAuthMethods bool
}

type Observer struct {
	Ready       func() error
	AuthMethods func([]auth.AuthInfo) error
}

// Session owns one protocol invocation; the ABI serializes starts and joins Run on stop.
// An injected dialer/writer remains owned by its caller, as in atrust.ClientOptions.
type Session struct{ options Options }

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
	var keyLog io.Closer
	var vpn *atrust.Client
	var network *gvisor.Stack
	var resolver *resolve.Resolver
	var listeners *service.Listeners
	defer func() {
		if keyLog != nil {
			if closeErr := keyLog.Close(); closeErr != nil {
				err = fmt.Errorf("keylog_close_failed: %w", closeErr)
			}
		}
	}()
	defer func() {
		if ownedUnderlay != nil {
			if closeErr := ownedUnderlay.Close(); closeErr != nil {
				err = fmt.Errorf("capture_close_failed: %w", closeErr)
			}
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
	clientOptions := options.Client
	if clientOptions.UnderlayDialer == nil {
		ownedUnderlay, err = underlay.New(options.Underlay)
		if err != nil {
			return fmt.Errorf("underlay_failed: %w", err)
		}
		clientOptions.UnderlayDialer = ownedUnderlay
	}
	if options.TLSKeyLogFile != "" {
		if clientOptions.TLSKeyLogWriter != nil {
			return errors.New("ambiguous_keylog_options")
		}
		file, openErr := keylog.Open(options.TLSKeyLogFile)
		if openErr != nil {
			return fmt.Errorf("keylog_failed: %w", openErr)
		}
		keyLog, clientOptions.TLSKeyLogWriter = file, file
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
	dialer := dial.NewDialer(network, resolver, ips, false, "")
	listeners, err = service.NewListeners(ctx, options.SOCKS, options.HTTP, dialer, resolver)
	if err != nil {
		return fmt.Errorf("listeners_failed: %w", err)
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
