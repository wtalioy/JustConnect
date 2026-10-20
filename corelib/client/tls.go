package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

// TLSHandshakeError preserves the handshake boundary without parsing error text.
type TLSHandshakeError struct{ Err error }

func (e *TLSHandshakeError) Error() string { return "TLS handshake failed" }
func (e *TLSHandshakeError) Unwrap() error { return e.Err }

func DialTLSContext(ctx context.Context, dial DialContextFunc, network, address string, config *tls.Config) (*tls.Conn, error) {
	if dial == nil {
		return nil, errors.New("underlay dialer is required")
	}
	raw, err := dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if config.ServerName == "" {
		config.ServerName, _, _ = net.SplitHostPort(address)
	}
	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, &TLSHandshakeError{Err: err}
	}
	return conn, nil
}
