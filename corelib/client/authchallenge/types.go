package authchallenge

import (
	"errors"
	"fmt"
)

var ErrUnsupported = errors.New("unsupported authentication step")

type CodeKind string

const (
	CodeSMS    CodeKind = "sms"
	CodeTOTP   CodeKind = "totp"
	CodeRadius CodeKind = "radius"
)

type CodeChallenge struct {
	Kind                 CodeKind
	CanSkipSecondaryAuth bool
}

type CodeResponse struct {
	Code              string
	SkipSecondaryAuth bool
}

type TextCaptchaChallenge struct {
	Image []byte
}

type TextCaptchaResponse struct {
	Code string
}

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type ClickCaptchaChallenge struct {
	Image []byte
}

type ClickCaptchaResponse struct {
	Points []Point
	Width  int
	Height int
}

type ExternalLoginKind string

const (
	ExternalLoginCAS    ExternalLoginKind = "cas"
	ExternalLoginOAuth2 ExternalLoginKind = "oauth2"
)

type ExternalLoginChallenge struct {
	Kind     ExternalLoginKind
	LoginURL string
}

type ExternalLoginResponse struct {
	CallbackURL string
}

type Handler interface {
	HandleTrustedDevice() (bool, error)
	HandleCodeChallenge(CodeChallenge) (CodeResponse, error)
	HandleTextCaptcha(TextCaptchaChallenge) (TextCaptchaResponse, error)
	HandleClickCaptcha(ClickCaptchaChallenge) (ClickCaptchaResponse, error)
	HandleExternalLogin(ExternalLoginChallenge) (ExternalLoginResponse, error)
}

type HandlerFuncs struct {
	TrustedDevice func() (bool, error)
	Code          func(CodeChallenge) (CodeResponse, error)
	TextCaptcha   func(TextCaptchaChallenge) (TextCaptchaResponse, error)
	ClickCaptcha  func(ClickCaptchaChallenge) (ClickCaptchaResponse, error)
	ExternalLogin func(ExternalLoginChallenge) (ExternalLoginResponse, error)
}

func (h HandlerFuncs) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	if h.Code == nil {
		return UnsupportedHandler{}.HandleCodeChallenge(challenge)
	}
	return h.Code(challenge)
}

func (h HandlerFuncs) HandleTextCaptcha(challenge TextCaptchaChallenge) (TextCaptchaResponse, error) {
	if h.TextCaptcha == nil {
		return UnsupportedHandler{}.HandleTextCaptcha(challenge)
	}
	return h.TextCaptcha(challenge)
}

func (h HandlerFuncs) HandleClickCaptcha(challenge ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	if h.ClickCaptcha == nil {
		return UnsupportedHandler{}.HandleClickCaptcha(challenge)
	}
	return h.ClickCaptcha(challenge)
}

func (h HandlerFuncs) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	if h.ExternalLogin == nil {
		return UnsupportedHandler{}.HandleExternalLogin(challenge)
	}
	return h.ExternalLogin(challenge)
}

func (h HandlerFuncs) HandleTrustedDevice() (bool, error) {
	if h.TrustedDevice == nil {
		return UnsupportedHandler{}.HandleTrustedDevice()
	}
	return h.TrustedDevice()
}

type UnsupportedHandler struct{}

func (UnsupportedHandler) HandleTrustedDevice() (bool, error) { return false, ErrUnsupported }

func (UnsupportedHandler) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	return CodeResponse{}, fmt.Errorf("%w: code %s", ErrUnsupported, challenge.Kind)
}

func (UnsupportedHandler) HandleTextCaptcha(TextCaptchaChallenge) (TextCaptchaResponse, error) {
	return TextCaptchaResponse{}, ErrUnsupported
}

func (UnsupportedHandler) HandleClickCaptcha(ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	return ClickCaptchaResponse{}, ErrUnsupported
}

func (UnsupportedHandler) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	return ExternalLoginResponse{}, fmt.Errorf("%w: external login %s", ErrUnsupported, challenge.Kind)
}
