package underlay

import (
	"context"
	"net"
	"time"

	socketdialer "github.com/wtalioy/JustConnect/corelib/internal/dialer"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
)

var discoverController = mihomo.Discover

func (d *Dialer) prepareController(ctx context.Context, address string) error {
	if d.localDNSServer != "" || isLoopbackAddress(address) {
		return nil
	}
	d.mu.Lock()
	if d.controllerGate == nil {
		d.controllerGate = make(chan struct{}, 1)
	}
	gate := d.controllerGate
	d.mu.Unlock()
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-gate }()
	d.mu.RLock()
	ready := d.controller != nil
	d.mu.RUnlock()
	if ready {
		return nil
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	controller, err := discoverController(deadline)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.diagnostic != nil {
			if err == mihomo.ErrAmbiguous {
				d.diagnostic("local_controller_ambiguous")
			} else {
				d.diagnostic("local_controller_unavailable")
			}
		}
		return err
	}
	if controller == nil {
		return nil
	}
	if controller.TunEnabled && controller.TunDevice == "" {
		controller.Close()
		return mihomo.ErrUnavailable
	}
	d.mu.Lock()
	d.controller = controller
	d.resolver = controller.Resolver()
	if controller.TunEnabled {
		d.tunDevice = controller.TunDevice
		d.requireBound = true
		if d.interfaceName == "" {
			d.autoDetect = true
		}
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

func (d *Dialer) isTunnel(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return mihomo.SameInterface(name, d.tunDevice)
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
