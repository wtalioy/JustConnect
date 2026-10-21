package auth

import (
	"context"
	"errors"
)

var ErrSessionInvalid = errors.New("aTrust session is invalid; reauthentication required")

// Snapshot must be taken after the last HTTP response, which may replace sid.
func (s *Session) Snapshot() (LoginResult, error) {
	sid, cookies := sessionCookies(s)
	if sid == "" {
		return LoginResult{}, ErrSessionInvalid
	}
	return LoginResult{SID: sid, Cookies: cookies}, nil
}

// Refresh maintains an existing session; it never starts an interactive login.
// Calls on the same Session must be serialized with login and other requests.
func (s *Session) Refresh(ctx context.Context) (LoginResult, error) {
	if _, _, err := s.authConfigContext(ctx, false, false, true); err != nil {
		return LoginResult{}, err
	}
	return s.Snapshot()
}
