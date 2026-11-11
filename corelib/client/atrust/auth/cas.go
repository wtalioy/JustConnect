package auth

import (
	"net/url"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

type CASLogin struct {
	Domain string
	Ticket string
}

func (m CASLogin) AuthType() string {
	return "auth/cas"
}

func (m CASLogin) LoginDomain() string {
	return m.Domain
}

func (m CASLogin) login(s *Session, authInfo AuthInfo) error {
	return s.loginAuthCas(authInfo.LoginURL, m.Domain, m.Ticket)
}

func (s *Session) loginAuthCas(loginURL, loginDomain, ticket string) error {
	callback := s.casCallbackFromTicket(loginDomain, ticket)
	if ticket == "" {
		var err error
		callback, err = s.interactiveCas(loginURL)
		if err != nil {
			return err
		}
	}

	if err := s.cas(callback); err != nil {
		return err
	}
	_, _, err := s.authConfig(true, false)
	return err
}

func (s *Session) casCallbackFromTicket(loginDomain, ticket string) string {
	params := url.Values{
		"sfDomain": {loginDomain},
		"ticket":   {ticket},
	}
	return s.baseURL + "/passport/v1/auth/cas?" + params.Encode()
}

func (s *Session) interactiveCas(loginURL string) (string, error) {
	response, err := s.challengeHandler.HandleExternalLogin(authchallenge.ExternalLoginChallenge{
		Kind:     authchallenge.ExternalLoginCAS,
		LoginURL: loginURL,
	})
	return response.CallbackURL, err
}

func (s *Session) cas(callback string) error {
	return s.exchangeAuthCallback(callback, "/passport/v1/auth/cas", "ticket")
}
