package auth

import (
	"errors"
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
