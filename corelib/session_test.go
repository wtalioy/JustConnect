package corelib

import (
	"context"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/atrust"
)

func TestSessionPanicDoesNotExposeCredentials(t *testing.T) {
	options := Options{Setup: atrust.SetupOptions{ServerAddress: "127.0.0.1", ServerPort: 443},
		Client: atrust.ClientOptions{Diagnostic: func(string) { panic("private credentials") }}}
	err := NewSession(options).Run(context.Background(), Observer{})
	if err == nil || err.Error() != "core_session_panicked" {
		t.Fatalf("panic error = %v", err)
	}
}
