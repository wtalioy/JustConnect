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

// UDP activity extends one flow deadline without replacing the connection's timers.
type udpIdleTimer struct {
	mu       sync.Mutex
	interval time.Duration
	deadline time.Time
	timer    *time.Timer
}

func newUDPIdleTimer(interval time.Duration, expire func()) *udpIdleTimer {
	idle := &udpIdleTimer{interval: interval, deadline: time.Now().Add(interval)}
	idle.mu.Lock()
	idle.timer = time.AfterFunc(interval, func() {
		idle.mu.Lock()
		if idle.deadline.IsZero() {
			idle.mu.Unlock()
			return
		}
		if remaining := time.Until(idle.deadline); remaining > 0 {
			idle.timer.Reset(remaining)
			idle.mu.Unlock()
			return
		}
		idle.deadline = time.Time{}
		idle.mu.Unlock()
		expire()
	})
	idle.mu.Unlock()
	return idle
}

func (idle *udpIdleTimer) touch() bool {
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if idle.deadline.IsZero() {
		return false
	}
	idle.deadline = time.Now().Add(idle.interval)
	return true
}

func (idle *udpIdleTimer) stop() {
	idle.mu.Lock()
	idle.deadline = time.Time{}
	idle.timer.Stop()
	idle.mu.Unlock()
}

func relayDatagrams(ctx context.Context, left, right net.Conn, idle time.Duration, fail func(error)) {
	if ctx.Err() != nil {
		_ = left.Close()
		_ = right.Close()
		return
	}
	closeBoth := sync.OnceFunc(func() { _ = left.Close(); _ = right.Close() })
	watch := newUDPIdleTimer(idle, closeBoth)
	defer watch.stop()
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
			if err != nil || ctx.Err() != nil || !watch.touch() {
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
