package service

import (
	"errors"
	"io"
	"net"
	"sync"
)

const streamBufferSize = 32 << 10 // io.Copy's fallback buffer size.

var streamBuffers = sync.Pool{New: func() any { return new([streamBufferSize]byte) }}

func relayStream(client io.Writer, reader io.Reader, target net.Conn, fail func(error)) {
	abort := sync.OnceFunc(func() {
		_ = target.Close()
		if closer, ok := client.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayDirection(target, reader, abort, fail)
	}()
	relayDirection(client, target, abort, fail)
	<-done
}

func relayDirection(dst io.Writer, src io.Reader, abort func(), fail func(error)) {
	var relayErr error
	defer func() {
		if recover() != nil {
			relayErr = errors.New("proxy relay panicked")
			if fail != nil {
				fail(relayErr)
			}
		}
		if relayErr != nil {
			abort()
		}
	}()
	var buffer []byte
	_, writesTo := src.(io.WriterTo)
	_, readsFrom := dst.(io.ReaderFrom)
	if !writesTo && !readsFrom {
		poolEntry := streamBuffers.Get().(*[streamBufferSize]byte)
		defer streamBuffers.Put(poolEntry)
		buffer = poolEntry[:]
	}
	_, relayErr = io.CopyBuffer(dst, src, buffer)
	// EOF ends one direction while the peer can still be preparing its response.
	if relayErr == nil {
		if conn, ok := dst.(interface{ CloseWrite() error }); ok {
			relayErr = conn.CloseWrite()
		}
	}
	if conn, ok := src.(interface{ CloseRead() error }); ok {
		_ = conn.CloseRead()
	}
}
