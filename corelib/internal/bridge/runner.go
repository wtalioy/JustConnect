package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
		Client:   atrust.ClientOptions{TLSConfig: tlsPolicy, Language: config.Network.Language, Diagnostic: func(code string) { host.Diagnostic(code) }},
		Setup:    atrust.SetupOptions{AuthID: config.Auth.AuthID, AuthSubType: config.Auth.SubType, ServerAddress: config.Server.Host, ServerPort: int(config.Server.Port), LoginMethod: method, TOTPSecret: config.Auth.TOTPSecret, ChallengeHandler: challengeHandler(ctx, host)},
		Underlay: underlay.Options{InterfaceName: config.Network.Interface, AutoDetect: config.Network.AutoDetect, LocalDNSServer: config.Network.LocalDNS},
		SOCKS:    config.Listeners.SOCKS, HTTP: config.Listeners.HTTP, SecondaryDNS: config.Network.SecondaryDNS, DNSCacheTTL: uint64(config.Network.DNSCacheTTL), DisableRemoteDNS: config.Network.DisableRemoteDNS,
		QueryAuthMethods: config.Operation == "auth_methods",
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
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	if errors.Is(err, authchallenge.ErrUnsupported) {
		return AuthUnsupported
	}
	if errors.Is(err, auth.ErrAuthMethodChanged) {
		return AuthMethodChanged
	}
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		return Limit
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return TLSTrust
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
