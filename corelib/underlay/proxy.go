package underlay

import (
	"context"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
)

// ObserveProxy shares discovery and lifecycle with control DNS, independently of its DNS override.
func (d *Dialer) ObserveProxy(parent context.Context, proofs []mihomo.ListenerProof) (mihomo.ProxyInfo, error) {
	ctx, finish, err := d.begin(parent)
	if err != nil {
		return mihomo.ProxyInfo{}, err
	}
	defer finish()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := d.ensureController(ctx); err != nil {
		return mihomo.ProxyInfo{}, err
	}
	d.mu.RLock()
	controller := d.controller
	d.mu.RUnlock()
	if controller == nil {
		return mihomo.ProxyInfo{}, nil
	}
	info, err := controller.ObserveProxy(ctx, proofs...)
	if err != nil {
		return mihomo.ProxyInfo{}, err
	}
	d.mu.Lock()
	if d.controller == controller {
		d.tunDevice = ""
		if info.TunEnabled {
			d.tunDevice = info.TunDevice
			d.requireOriginalExit()
			if d.autoDetect && mihomo.SameInterface(d.interfaceName, d.tunDevice) {
				d.interfaceName = ""
			}
		}
	}
	d.mu.Unlock()
	return info, nil
}
