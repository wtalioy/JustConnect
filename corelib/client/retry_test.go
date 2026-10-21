package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"net"
	"testing"
)

func TestRetryOnlyTransportFailures(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, context.DeadlineExceeded, &net.DNSError{IsTemporary: true},
		&TLSHandshakeError{Err: &net.OpError{Op: "read", Err: net.ErrClosed}}, &net.OpError{Op: "dial", Err: net.ErrClosed}} {
		if !RetryableTransportError(err) {
			t.Fatal("lost recoverable transport failure", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, &net.DNSError{IsNotFound: true},
		&TLSHandshakeError{Err: &net.OpError{Op: "remote error", Err: errors.New("protocol alert")}}, &net.OpError{Op: "dial", Err: fs.ErrPermission}, &net.OpError{Op: "listen", Err: net.ErrClosed}, &TLSHandshakeError{Err: io.EOF},
		errors.Join(context.DeadlineExceeded, &tls.CertificateVerificationError{Err: errors.New("untrusted")}),
		errors.Join(context.DeadlineExceeded, fs.ErrPermission), errors.New("wrong credentials or rate limit")} {
		if RetryableTransportError(err) {
			t.Fatal("unsafe automatic retry", err)
		}
	}
}
