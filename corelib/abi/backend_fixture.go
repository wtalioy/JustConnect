//go:build cgo && jc_abi_test

package main

import (
	"context"
	"runtime"

	"github.com/wtalioy/JustConnect/corelib/internal/bridge"
)

// Test-only driver exercises the real C exports and transport, without network I/O.
var engine = bridge.New(func(ctx context.Context, config bridge.Config, session *bridge.Session) bridge.Status {
	response, status := session.Authenticate(ctx, bridge.Challenge{Kind: "sms"})
	if status != bridge.OK {
		return status
	}
	// Cross another asynchronous boundary before using copied host credentials.
	runtime.GC()
	if response.Code != config.Auth.Password {
		return bridge.Internal
	}
	if status = session.Ready(); status != bridge.OK {
		return status
	}
	<-ctx.Done()
	return bridge.Cancelled
})

const testDriver = true
