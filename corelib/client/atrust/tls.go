package atrust

import (
	"context"
	"crypto/tls"

	"github.com/wtalioy/JustConnect/corelib/client"
)

func tlsConfig(config *tls.Config) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	return config
}

func (c *Client) dialTunnelTLS(ctx context.Context, network, address string) (*tls.Conn, error) {
	return client.DialTLSContext(ctx, c.underlayDialer.DialContext, network, address, c.tunnelTLSPolicy)
}
