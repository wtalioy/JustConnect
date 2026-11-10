package service

import (
	"context"
	"errors"
	"net"
	"sync"
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
	closeBoth := sync.OnceFunc(func() { _ = left.Close(); _ = right.Close() })
	// gVisor recreates read and write timers on each SetDeadline call.
	var mu sync.Mutex
	deadline := time.Now().Add(idle)
	var timer *time.Timer
	mu.Lock()
	timer = time.AfterFunc(idle, func() {
		mu.Lock()
		if deadline.IsZero() {
			mu.Unlock()
			return
		}
		if remaining := time.Until(deadline); remaining > 0 {
			timer.Reset(remaining)
			mu.Unlock()
			return
		}
		deadline = time.Time{}
		mu.Unlock()
		closeBoth()
	})
	mu.Unlock()
	defer func() {
		mu.Lock()
		deadline = time.Time{}
		timer.Stop()
		mu.Unlock()
	}()
	refresh := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if deadline.IsZero() {
			return false
		}
		deadline = time.Now().Add(idle)
		return true
	}
	copyPackets := func(dst, src net.Conn) {
		defer closeBoth()
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
			if err != nil || ctx.Err() != nil || !refresh() {
				return
			}
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
