package underlay

import (
	"context"
	"net"
)

func (d *Dialer) begin(ctx context.Context) (context.Context, func(), error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	d.active.Add(1)
	d.mu.Unlock()
	if d.lifecycleCtx == nil {
		return ctx, d.active.Done, nil
	}
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.lifecycleCtx, cancel)
	return child, func() { stop(); cancel(); d.active.Done() }, nil
}
