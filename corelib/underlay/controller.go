package underlay

import (
	"context"
	"net"
	"time"

	socketdialer "github.com/wtalioy/JustConnect/corelib/internal/dialer"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
)

var discoverController = mihomo.Discover

type controllerCheck struct {
	done  chan struct{}
	err   error
	retry bool
}

func (d *Dialer) ensureController(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		d.mu.Lock()
		if pending := d.controllerCheck; pending != nil {
			d.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-pending.done:
			}
			if pending.retry {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return pending.err
		}
		if d.controller != nil {
			if d.controller.Alive() {
				d.mu.Unlock()
				return nil
			}
			d.controller.Close()
			d.controller, d.resolver, d.tunDevice = nil, nil, ""
		}
		pending := &controllerCheck{done: make(chan struct{})}
		d.controllerCheck = pending
		d.mu.Unlock()

		return d.findController(ctx, pending)
	}
}

func (d *Dialer) findController(ctx context.Context, pending *controllerCheck) (err error) {
	err = mihomo.ErrUnavailable
	defer func() {
		d.mu.Lock()
		// Share absence only with concurrent callers; a later dial must see a newly started controller.
		pending.err, pending.retry = err, err != nil && ctx.Err() != nil
		d.controllerCheck = nil
		close(pending.done)
		d.mu.Unlock()
	}()
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	controller, discoverErr := discoverController(deadline, d.controllerAddress)
	if discoverErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.diagnostic != nil {
			if discoverErr == mihomo.ErrAmbiguous {
				d.diagnostic("local_controller_ambiguous")
			} else {
				d.diagnostic("local_controller_unavailable")
			}
		}
		return discoverErr
	}
	if controller == nil {
		return nil
	}
	d.mu.Lock()
	d.controller = controller
	if d.localDNSServer == "" {
		d.resolver = controller.Resolver()
	}
	if controller.TunEnabled {
		d.tunDevice = controller.TunDevice
		d.requireOriginalExit()
		if d.autoDetect && mihomo.SameInterface(d.interfaceName, d.tunDevice) {
			d.interfaceName = ""
		}
	}
	if d.autoDetect && d.interfaceName == "" && controller.OutboundInterface != "" && usableInterface(controller.OutboundInterface, d.excludedIPs) && !mihomo.SameInterface(controller.OutboundInterface, d.tunDevice) {
		d.updateInterfaceName(controller.OutboundInterface)
	}
	d.mu.Unlock()
	if d.diagnostic != nil {
		d.diagnostic("local_controller_real_dns")
	}
	return nil
}

func (d *Dialer) dial(ctx context.Context, network, address, interfaceName string) (net.Conn, error) {
	d.mu.RLock()
	resolver := d.resolver
	d.mu.RUnlock()
	if resolver == nil {
		return dialOnInterface(ctx, network, address, interfaceName, d.localDNSServer)
	}
	return (&socketdialer.Dialer{InterfaceName: interfaceName, Resolver: resolver, UnboundLoopback: true}).DialContext(ctx, network, address)
}
