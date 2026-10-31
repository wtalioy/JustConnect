package bridge

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
)

func (e *Engine) NetworkSnapshot() (model.Snapshot, error) {
	snapshot, err := networkstate.Read()
	if err != nil || snapshot.OS != "linux" {
		return snapshot, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.mu.Lock()
	active := e.active
	e.mu.Unlock()
	var observation mihomo.ControllerNetwork
	if active != nil {
		active.mu.Lock()
		protocol, lifecycle := active.protocol, active.ctx
		active.mu.Unlock()
		if lifecycle != nil {
			stop := context.AfterFunc(lifecycle, cancel)
			defer stop()
		}
		if protocol != nil {
			observation, err = protocol.ObserveNetwork(ctx)
		} else {
			err = net.ErrClosed
		}
	}
	if active == nil || errors.Is(err, net.ErrClosed) {
		controller, discoveryErr := mihomo.Discover(ctx)
		if discoveryErr == nil && controller != nil {
			defer controller.Close()
			observation, err = controller.ObserveNetwork(ctx)
		}
	}
	// Unconfirmed local controllers never remove original-network protection.
	if err != nil || !observation.NetworkAdmin || observation.Device == "" {
		return snapshot, nil
	}
	snapshot.ProxyTunnel = networkstate.ObserveProxyTunnel(snapshot, observation.Device)
	return snapshot, nil
}
