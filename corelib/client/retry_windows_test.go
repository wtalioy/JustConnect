package client

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestWinsockPermissionDenialNeverRetries(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connectex", Err: syscall.WSAEACCES}}
	for _, failure := range []error{err, errors.Join(context.DeadlineExceeded, err)} {
		if !IsPermissionError(failure) || RetryableTransportError(failure) {
			t.Fatal("Winsock access denial was treated as a transient network failure", failure)
		}
	}
}
