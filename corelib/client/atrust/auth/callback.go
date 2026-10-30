package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func sameCallbackHost(a, b string) bool {
	left, leftErr := netip.ParseAddr(a)
	right, rightErr := netip.ParseAddr(b)
	if leftErr == nil || rightErr == nil {
		return leftErr == nil && rightErr == nil && left == right
	}
	return strings.EqualFold(a, b)
}

func httpsPort(u *url.URL) int {
	if u.Port() == "" {
		return 443
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

// Validate at the request boundary, including callbacks supplied without a browser.
func parseAuthCallback(baseURL, raw, path, token string) (*url.URL, error) {
	callback, err := url.Parse(raw)
	base, baseErr := url.Parse(baseURL)
	invalid := errors.New("invalid external login callback")
	if err != nil || baseErr != nil || callback.Scheme != "https" || base.Scheme != "https" || callback.Opaque != "" || callback.User != nil ||
		strings.Contains(raw, "#") || callback.Hostname() == "" || !sameCallbackHost(callback.Hostname(), base.Hostname()) ||
		httpsPort(callback) == 0 || httpsPort(callback) != httpsPort(base) || callback.EscapedPath() != path {
		return nil, invalid
	}
	query, err := url.ParseQuery(callback.RawQuery)
	if err != nil || len(query[token]) != 1 || strings.TrimSpace(query.Get(token)) == "" || strings.ContainsAny(query.Get(token), "\x00\r\n") {
		return nil, invalid
	}
	return callback, nil
}

func (s *Session) exchangeAuthCallback(callback, path, token string) error {

	callbackURL, err := parseAuthCallback(s.baseURL, callback, path, token)
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
	if resp.StatusCode != http.StatusFound {
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
