package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

type operationStatus struct{ status Status }

func (e operationStatus) Error() string { return e.status.Message() }
func checkStatus(status Status) error {
	if status != OK {
		return operationStatus{status}
	}
	return nil
}

// RunProtocol returns after protocol, stack, resolver, and listener cleanup completes.
func RunProtocol(ctx context.Context, config Config, host *Session) Status {
	method, err := auth.NewLoginMethod(auth.LoginMethodOptions{AuthType: config.Auth.Method, Username: config.Auth.Username, Password: config.Auth.Password, Phone: config.Auth.Phone, Domain: config.Auth.Domain})
	if err != nil {
		return InvalidArgument
	}
	tlsPolicy := &tls.Config{InsecureSkipVerify: config.TLS.SkipVerify}
	if config.TLS.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(config.TLS.CAPEM)) {
			return InvalidArgument
		}
		tlsPolicy.RootCAs = roots
	}
	options := corelib.Options{
		Client:   atrust.ClientOptions{TLSConfig: tlsPolicy, AllowUnverifiedNodes: config.TLS.AllowUnverifiedNodes, Language: config.Network.Language, Diagnostic: func(code string) { host.Diagnostic(code) }, Observe: func(stage, result string) { host.Observe(stage, result) }},
		Setup:    atrust.SetupOptions{AuthID: config.Auth.AuthID, AuthSubType: config.Auth.SubType, ServerAddress: config.Server.Host, ServerPort: int(config.Server.Port), LoginMethod: method, TOTPSecret: config.Auth.TOTPSecret, ChallengeHandler: challengeHandler(ctx, host)},
		Underlay: underlay.Options{InterfaceName: config.Network.Interface, AutoDetect: config.Network.AutoDetect, LocalDNSServer: config.Network.LocalDNS},
		SOCKS:    config.Listeners.SOCKS, HTTP: config.Listeners.HTTP, SecondaryDNS: config.Network.SecondaryDNS, DNSCacheTTL: uint64(config.Network.DNSCacheTTL), DisableRemoteDNS: config.Network.DisableRemoteDNS,
		QueryAuthMethods: config.Operation == "auth_methods",
	}
	if config.AuthenticationCache.Enabled {
		options.Client.Session.Username = config.AuthenticationCache.Account
		options.Setup.ClientData = config.AuthenticationCache.Data
		options.Setup.SaveClientData = func(data []byte) error {
			var snapshot auth.ClientAuthData
			if json.Unmarshal(data, &snapshot) != nil || host.SaveAuthenticationCache(snapshot.Identity.Username, data) != OK {
				host.Diagnostic("persistence_failed")
			}
			return nil // Persistence is optional; a valid live session remains usable.
		}
		options.Setup.ClientDataInvalidated = func() { host.InvalidateAuthenticationCache() }
	}
	err = corelib.NewSession(options).Run(ctx, corelib.Observer{
		Ready: func() error { return checkStatus(host.Ready()) },
		AuthMethods: func(list []auth.AuthInfo) error {
			methods := make([]AuthMethod, len(list))
			for i, m := range list {
				methods[i] = AuthMethod{AuthID: m.AuthID, SubType: m.SubType, Type: m.AuthType, Domain: m.LoginDomain, Name: m.AuthName, LoginURL: m.LoginURL}
			}
			return checkStatus(host.AuthMethods(methods))
		},
	})
	if err == nil {
		return OK
	}
	var status operationStatus
	if errors.As(err, &status) {
		return status.status
	}
	if errors.Is(err, context.Canceled) {
		return Cancelled
	}
	if errors.Is(err, authchallenge.ErrUnsupported) {
		return AuthUnsupported
	}
	if errors.Is(err, auth.ErrAuthMethodChanged) {
		return AuthMethodChanged
	}
	if errors.Is(err, auth.ErrSessionInvalid) {
		return SessionInvalid
	}
	if errors.Is(err, auth.ErrCredentialsRequired) {
		return CredentialsRequired
	}
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		return Limit
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		if config.Operation == "auth_methods" {
			host.Diagnostic("tls_authentication_failed")
		}
		for _, code := range certificateDiagnostics(certificate) {
			host.Diagnostic(code)
		}
		return TLSTrust
	}
	// Joined node failures may contain both a certificate rejection and a timeout.
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return Timeout
	}
	var socket *net.OpError
	if errors.As(err, &socket) && socket.Op != "listen" {
		return NetworkFailure
	}
	var handshake *client.TLSHandshakeError
	if errors.As(err, &handshake) {
		return TLSProtocol
	}
	return Internal
}

func certificateDiagnostics(failure *tls.CertificateVerificationError) []string {
	codes := []string{certificateDiagnostic(failure.Err)}
	if len(failure.UnverifiedCertificates) == 0 {
		return codes
	}
	if len(failure.UnverifiedCertificates) == 1 {
		codes = append(codes, "tls_peer_chain_leaf_only")
	}
	leaf := failure.UnverifiedCertificates[0]
	if bytes.Equal(leaf.RawSubject, leaf.RawIssuer) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		codes = append(codes, "tls_peer_self_signed")
	}
	return codes
}

func certificateDiagnostic(err error) string {
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &authority):
		return "tls_unknown_authority"
	case errors.As(err, &hostname):
		return "tls_hostname_mismatch"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "tls_certificate_time_invalid"
	default:
		return "tls_certificate_invalid"
	}
}

func challengeHandler(ctx context.Context, host *Session) authchallenge.Handler {
	ask := func(challenge Challenge) (Response, error) {
		response, status := host.Authenticate(ctx, challenge)
		return response, checkStatus(status)
	}
	return authchallenge.HandlerFuncs{
		TrustedDevice: func() (bool, error) {
			r, err := ask(Challenge{Kind: "trusted_device"})
			return r.Action == "confirm", err
		},
		Code: func(c authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			r, err := ask(Challenge{Kind: string(c.Kind), CanSkipSecondaryAuth: c.CanSkipSecondaryAuth})
			return authchallenge.CodeResponse{Code: r.Code, SkipSecondaryAuth: r.SkipSecondaryAuth}, err
		},
		TextCaptcha: func(c authchallenge.TextCaptchaChallenge) (authchallenge.TextCaptchaResponse, error) {
			r, err := ask(Challenge{Kind: "text_captcha", Image: c.Image})
			return authchallenge.TextCaptchaResponse{Code: r.Code}, err
		},
		ClickCaptcha: func(c authchallenge.ClickCaptchaChallenge) (authchallenge.ClickCaptchaResponse, error) {
			r, err := ask(Challenge{Kind: "click_captcha", Image: c.Image})
			points := make([]authchallenge.Point, len(r.Points))
			for i, p := range r.Points {
				points[i] = authchallenge.Point{X: p.X, Y: p.Y}
			}
			return authchallenge.ClickCaptchaResponse{Points: points, Width: r.Width, Height: r.Height}, err
		},
		ExternalLogin: func(c authchallenge.ExternalLoginChallenge) (authchallenge.ExternalLoginResponse, error) {
			r, err := ask(Challenge{Kind: string(c.Kind), LoginURL: c.LoginURL})
			return authchallenge.ExternalLoginResponse{CallbackURL: r.CallbackURL}, err
		},
	}
}
