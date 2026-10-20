package client_test

import (
	"context"
	"net"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

type externalUnderlay struct{}

func (externalUnderlay) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (externalUnderlay) ExcludeIP(net.IP) {}

var (
	_ client.UnderlayDialer = externalUnderlay{}
	_ client.UnderlayDialer = (*underlay.Dialer)(nil)
)

func TestPublicATrustClientAcceptsExternalUnderlay(t *testing.T) {
	var dialer client.UnderlayDialer = externalUnderlay{}

	aTrustClient := atrust.NewClient(atrust.ClientOptions{UnderlayDialer: dialer})
	if aTrustClient == nil {
		t.Fatal("atrust.NewClient returned nil")
	}
	aTrustClient.Close()
}
