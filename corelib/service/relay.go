package service

import (
	"errors"
	"io"
	"net"
)

func relayStream(client io.Writer, reader io.Reader, target net.Conn, fail func(error)) {
	done := make(chan error, 2)
	go relayDirection(target, reader, done, fail)
	go relayDirection(client, target, done, fail)
	// EOF ends one direction; the peer may still be preparing its response.
	if err := <-done; err != nil {
		_ = target.Close()
		if closer, ok := client.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	<-done
}

func relayDirection(dst io.Writer, src io.Reader, done chan<- error, fail func(error)) {
	var relayErr error
	defer func() {
		if recover() != nil {
			relayErr = errors.New("proxy relay panicked")
			if fail != nil {
				fail(relayErr)
			}
		}
		done <- relayErr
	}()
	_, relayErr = io.Copy(dst, src)
	if relayErr == nil {
		if conn, ok := dst.(interface{ CloseWrite() error }); ok {
			relayErr = conn.CloseWrite()
		}
	}
	if conn, ok := src.(interface{ CloseRead() error }); ok {
		_ = conn.CloseRead()
	}
}
