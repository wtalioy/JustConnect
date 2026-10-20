package atrust

import (
	"crypto/tls"
	"io"
)

func tlsConfig(config *tls.Config, keyLogWriter io.Writer) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if keyLogWriter != nil {
		config.KeyLogWriter = keyLogWriter
	}
	return config
}

func tunnelTLSConfig(config *tls.Config) *tls.Config {
	config = tlsConfig(config, nil)
	config.SessionTicketsDisabled = true
	return config
}
