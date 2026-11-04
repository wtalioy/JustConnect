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
	"github.com/wtalioy/JustConnect/corelib/policy"
)

const authenticationExitTimeout = time.Second

// Keep the selected external login reachable on the original network when campus capture overlaps it.
func originalAuthenticationAddress(ctx context.Context, method auth.LoginMethod, trust *tls.Config, dial client.DialContextFunc) netip.Addr {
	if method == nil || (method.AuthType() != "auth/cas" && method.AuthType() != "auth/httpsOauth2") {
		return netip.Addr{}
	}
	host := strings.TrimSuffix(strings.ToLower(method.LoginDomain()), ".")
	name := policy.NameRule{Kind: "exact", Value: host}
	if !name.Matches(host) || !strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") {
		return netip.Addr{}
	}
	ctx, cancel := context.WithTimeout(ctx, authenticationExitTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return netip.Addr{}
	}
	defer conn.Close()
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	address := peer.Addr().Unmap()
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
		return netip.Addr{}
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if trust != nil {
		config.RootCAs = trust.RootCAs
	}
	if tls.Client(conn, config).HandshakeContext(ctx) != nil {
		return netip.Addr{}
	}
	// shortcut: Preserve the verified peer for this session; refresh on reconnect if DNS moves.
	return address
}
