package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"net"
)

// RetryableTransportError excludes local policy, trust and protocol failures before unwrapping sockets.
func RetryableTransportError(err error) bool {
	var certificate *tls.CertificateVerificationError
	var handshake *TLSHandshakeError
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, fs.ErrPermission) || errors.As(err, &certificate) {
		return false
	}
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		return true
	}
	if errors.As(err, &handshake) {
		var socket *net.OpError
		return errors.As(err, &socket) && (socket.Op == "read" || socket.Op == "write")
	}
	var lookup *net.DNSError
	if errors.As(err, &lookup) {
		return lookup.IsTemporary
	}
	var socket *net.OpError
	if errors.As(err, &socket) {
		return socket.Op != "listen"
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}
