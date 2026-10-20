package ping

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
)

// TCPing ...
type TCPing struct {
	target    *Target
	done      chan struct{}
	stop      chan struct{}
	result    *Result
	dial      client.DialContextFunc
	tlsPolicy *tls.Config

	startOnce sync.Once
	stopOnce  sync.Once
	runMu     sync.Mutex
	cancelRun context.CancelFunc
}

// SetDialContext overrides the system dialer used by TCPing.
func (tcping *TCPing) SetDialContext(dial client.DialContextFunc) {
	tcping.dial = dial
}

// SetTLSConfig uses the same trust policy as the session's authenticated traffic.
func (tcping *TCPing) SetTLSConfig(config *tls.Config) {
	if config != nil {
		tcping.tlsPolicy = config.Clone()
	}
}

// NewTCPing return a new TCPing
func NewTCPing() *TCPing {
	return &TCPing{
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}
}

// SetTarget set target for TCPing
func (tcping *TCPing) SetTarget(target *Target) {
	tcping.target = target
	if tcping.result == nil {
		tcping.result = &Result{Target: target}
	}
}

// Result return the result
func (tcping *TCPing) Result() *Result {
	return tcping.result
}

// StartWithContext starts the probe loop with caller-owned cancellation.
func (tcping *TCPing) StartWithContext(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		ctx = context.Background()
	}
	tcping.startOnce.Do(func() {
		runCtx, cancelRun := context.WithCancel(ctx)
		tcping.runMu.Lock()
		tcping.cancelRun = cancelRun
		tcping.runMu.Unlock()
		go func() {
			defer close(tcping.done)
			defer func() {
				if recover() != nil && tcping.result != nil {
					tcping.result.Err = errors.New("node probe panicked")
				}
			}()
			defer func() {
				cancelRun()
				tcping.runMu.Lock()
				tcping.cancelRun = nil
				tcping.runMu.Unlock()
			}()
			tcping.run(runCtx)
		}()
	})
	return tcping.done
}

func (tcping *TCPing) run(ctx context.Context) {
	if tcping.target == nil || tcping.result == nil {
		return
	}
	if tcping.target.Interval <= 0 || tcping.target.Timeout <= 0 {
		tcping.result.Err = errors.New("invalid node probe timing")
		return
	}
	ticker := time.NewTicker(tcping.target.Interval)
	defer ticker.Stop()
	for {
		if tcping.target.Counter != 0 && tcping.result.Counter >= tcping.target.Counter {
			if tcping.result.SuccessCounter > 0 {
				tcping.result.Err = nil
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tcping.stop:
			return
		case <-ticker.C:
		}

		duration, _, err := tcping.ping(ctx)
		if ctx.Err() != nil {
			return
		}
		tcping.result.Counter++
		if err != nil {
			tcping.result.Err = err
			continue
		}

		if tcping.result.MinDuration == 0 {
			tcping.result.MinDuration = duration
		}
		if tcping.result.MaxDuration == 0 {
			tcping.result.MaxDuration = duration
		}
		tcping.result.SuccessCounter++
		if duration > tcping.result.MaxDuration {
			tcping.result.MaxDuration = duration
		} else if duration < tcping.result.MinDuration {
			tcping.result.MinDuration = duration
		}
		tcping.result.TotalDuration += duration
	}
}

// Stop interrupts the current probe, including an in-flight dial or TLS handshake.
func (tcping *TCPing) Stop() {
	tcping.stopOnce.Do(func() {
		close(tcping.stop)
	})
	tcping.runMu.Lock()
	cancelRun := tcping.cancelRun
	tcping.runMu.Unlock()
	if cancelRun != nil {
		cancelRun()
	}
}

func (tcping *TCPing) ping(parent context.Context) (time.Duration, net.Addr, error) {
	ctx, cancel := context.WithTimeout(parent, tcping.target.Timeout)
	defer cancel()

	startedAt := time.Now()
	dial := (&net.Dialer{}).DialContext
	if tcping.dial != nil {
		dial = tcping.dial
	}
	conn, err := client.DialTLSContext(ctx, dial, "tcp", net.JoinHostPort(tcping.target.Host, strconv.Itoa(tcping.target.Port)), tcping.tlsPolicy)
	if err != nil {
		return 0, nil, contextError(ctx, err)
	}
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()
	return time.Since(startedAt), remoteAddr, nil
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
