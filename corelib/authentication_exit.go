package corelib

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

const authenticationExitTimeout = time.Second

// Keep the selected external login reachable on the original network when campus capture overlaps it.
func originalAuthenticationOrigin(ctx context.Context, method auth.LoginMethod, trust *tls.Config, connect client.DialContextFunc) dial.AuthenticationOrigin {
	if method == nil || (method.AuthType() != "auth/cas" && method.AuthType() != "auth/httpsOauth2") {
		return dial.AuthenticationOrigin{}
	}
	host := strings.TrimSuffix(strings.ToLower(method.LoginDomain()), ".")
	name := policy.NameRule{Kind: "exact", Value: host}
	if !name.Matches(host) || !strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") {
		return dial.AuthenticationOrigin{}
	}
	ctx, cancel := context.WithTimeout(ctx, authenticationExitTimeout)
	defer cancel()
	conn, err := connect(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return dial.AuthenticationOrigin{}
	}
	defer conn.Close()
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return dial.AuthenticationOrigin{}
	}
	address := peer.Addr().Unmap()
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
		return dial.AuthenticationOrigin{}
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if trust != nil {
		config.RootCAs = trust.RootCAs
	}
	if tls.Client(conn, config).HandshakeContext(ctx) != nil {
		return dial.AuthenticationOrigin{}
	}
	// shortcut: Preserve the verified peer for this session; refresh on reconnect if DNS moves.
	return dial.AuthenticationOrigin{Name: host, Address: address}
}
