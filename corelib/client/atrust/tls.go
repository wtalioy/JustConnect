package atrust

import (
	"crypto/tls"
)

func tlsConfig(config *tls.Config) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	return config
}

func tunnelTLSConfig(config *tls.Config) *tls.Config {
	config = tlsConfig(config)
	config.SessionTicketsDisabled = true
	return config
}
