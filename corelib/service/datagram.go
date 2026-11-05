package service

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	maxUDPPacket   = 1<<16 - 1
	udpIdleTimeout = 90 * time.Second
)

func relayDatagrams(ctx context.Context, left, right net.Conn, idle time.Duration, fail func(error)) {
	if ctx.Err() != nil {
		_ = left.Close()
		_ = right.Close()
		return
	}
	refresh := func() {
		deadline := time.Now().Add(idle)
		_ = left.SetDeadline(deadline)
		_ = right.SetDeadline(deadline)
	}
	refresh()
	copyPackets := func(dst, src net.Conn) {
		defer func() { _ = left.Close(); _ = right.Close() }()
		defer func() {
			if recover() != nil {
				fail(errors.New("TUN datagram relay panicked"))
			}
		}()
		if ctx.Err() != nil {
			return
		}
		buf := make([]byte, maxUDPPacket)
		for ctx.Err() == nil {
			n, err := src.Read(buf)
			if err != nil || ctx.Err() != nil {
				return
			}
			refresh()
			if written, err := dst.Write(buf[:n]); err != nil || written != n {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); copyPackets(left, right) }()
	copyPackets(right, left)
	<-done
}
