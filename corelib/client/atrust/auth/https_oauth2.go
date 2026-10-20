package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

type HTTPSOauth2Login struct {
	Domain   string
	Code     string
	Callback string
}

func (m HTTPSOauth2Login) AuthType() string {
	return "auth/httpsOauth2"
}

func (m HTTPSOauth2Login) LoginDomain() string {
	return m.Domain
}

func (m HTTPSOauth2Login) login(s *Session, authInfo AuthInfo) error {
	return s.loginAuthHttpsOauth2(authInfo.LoginURL, m.Domain, m.Code, m.Callback)
}

func (s *Session) loginAuthHttpsOauth2(loginURL, loginDomain, code, callback string) error {
	if callback == "" && code != "" {
		callback = s.httpsOauth2CallbackFromCode(loginDomain, code)
	}
	if callback == "" {
		var err error
		callback, err = s.interactiveHttpsOauth2(loginURL)
		if err != nil {
			return err
		}
	}

	if err := s.httpsOauth2(callback); err != nil {
		return err
	}

	_, _, err := s.authConfig(true, false)
	return err
}

func (s *Session) httpsOauth2CallbackFromCode(loginDomain, code string) string {
	params := url.Values{
		"sfDomain": {loginDomain},
		"code":     {code},
		"state":    {"null"},
	}
	return s.baseURL + "/passport/v1/auth/httpsOauth2?" + params.Encode()
}

func (s *Session) interactiveHttpsOauth2(loginURL string) (string, error) {
	response, err := s.challengeHandler.HandleExternalLogin(authchallenge.ExternalLoginChallenge{
		Kind:     authchallenge.ExternalLoginOAuth2,
		LoginURL: loginURL,
	})
	return response.CallbackURL, err
}

func (s *Session) httpsOauth2(callback string) error {

	callbackURL, err := parseAuthCallback(s.baseURL, callback, "/passport/v1/auth/httpsOauth2", "code")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, callbackURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	prevCheckRedirect := s.client.CheckRedirect
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { s.client.CheckRedirect = prevCheckRedirect }()

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != 302 {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	ticket, err := parsePortalTicketFromRedirect(resp.Header.Get("Location"), s.baseHost)
	if err != nil {
		return err
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	s.ticket = ticket
	return nil
}
