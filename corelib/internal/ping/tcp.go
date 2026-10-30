package ping

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
)

// Probe measures TLS reachability; the caller owns concurrency and cancellation.
func Probe(ctx context.Context, target Target, dial client.DialContextFunc, tlsPolicy *tls.Config) (result Result) {
	defer func() {
		if recover() != nil {
			result.Err = errors.New("node probe panicked")
		}
	}()
	if target.Interval <= 0 || target.Timeout <= 0 || target.Counter <= 0 {
		result.Err = errors.New("invalid node probe timing")
		return
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ticker := time.NewTicker(target.Interval)
	defer ticker.Stop()
	for result.Counter < target.Counter {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		duration, err := probeOnce(ctx, target, dial, tlsPolicy)
		if ctx.Err() != nil {
			return
		}
		result.Counter++
		if err != nil {
			result.Err = err
			continue
		}
		result.SuccessCounter++
		result.TotalDuration += duration
	}
	if result.SuccessCounter > 0 {
		result.Err = nil
	}
	return
}

func probeOnce(parent context.Context, target Target, dial client.DialContextFunc, tlsPolicy *tls.Config) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, target.Timeout)
	defer cancel()
	started := time.Now()
	conn, err := client.DialTLSContext(ctx, dial, "tcp", target.Address, tlsPolicy)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	defer conn.Close()
	return time.Since(started), nil
}
