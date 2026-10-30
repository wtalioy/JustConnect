package underlay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	tun "github.com/mythologyli/sing-tun"
	socketdialer "github.com/wtalioy/JustConnect/corelib/internal/dialer"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate"

	"github.com/sagernet/sing/common/logger"
)

// Dialer creates connections on the interface that was used to reach the VPN
// server before the TUN interface was installed. This prevents VPN underlay
// connections from being captured by the TUN interface itself.
type Dialer struct {
	mu             sync.RWMutex
	detecting      chan struct{}
	lifecycleCtx   context.Context
	cancel         context.CancelFunc
	active         sync.WaitGroup
	closed         bool
	closeOnce      sync.Once
	interfaceName  string
	originalSource netip.Addr
	autoDetect     bool
	excludedIPs    []net.IP
	requireBound   bool
	localDNSServer string
	controller     *mihomo.Client
	controllerGate chan struct{}
	resolver       *net.Resolver
	tunDevice      string
	diagnostic     func(string)
}

// Options configures a Dialer.
type Options struct {
	// InterfaceName explicitly selects the interface used by underlay sockets.
	// It takes precedence over AutoDetect.
	InterfaceName string
	// Known VPN addresses or an external TUN require an original exit even when AutoDetect is false.
	AutoDetect bool
	// LocalDNSServer overrides the system DNS for VPN server hostname resolution.
	// It must be an IP address with an optional port.
	LocalDNSServer string
	Diagnostic     func(string)
}

// New creates an underlay dialer. With no options, interface auto-detection is
// enabled. The caller must close the returned dialer.
func New(options ...Options) (*Dialer, error) {
	option := Options{AutoDetect: true}
	if len(options) > 0 {
		option = options[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{autoDetect: option.AutoDetect, lifecycleCtx: ctx, cancel: cancel, diagnostic: option.Diagnostic}
	localDNSServer, err := normalizeLocalDNSServer(option.LocalDNSServer)
	if err != nil {
		cancel()
		return nil, err
	}
	d.localDNSServer = localDNSServer
	if option.InterfaceName != "" {
		d.updateInterfaceName(option.InterfaceName)
		d.autoDetect = false
	}
	return d, nil
}

// InterfaceName reports the current socket preference; an empty name uses system routing.
func (d *Dialer) InterfaceName() string {
	if d == nil {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return ""
	}
	return d.interfaceName
}

// Close cancels active control work and joins it before releasing the controller.
func (d *Dialer) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		if d.cancel != nil {
			d.cancel()
		}
		d.mu.Unlock()
		d.active.Wait()
		if d.controller != nil {
			d.controller.Close()
		}
	})
}

// ExcludeIP prevents an interface carrying ip from being selected as the
// underlay. VPN clients use this to exclude their own TUN interface.
func (d *Dialer) ExcludeIP(ip net.IP) {
	if d == nil || ip == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.excludedIPs = append(d.excludedIPs, append(net.IP(nil), ip...))
	d.requireOriginalExit()
}

// Caller holds mu. A known VPN path cannot leave its control sockets unbound.
func (d *Dialer) requireOriginalExit() {
	d.requireBound = true
	if d.interfaceName == "" {
		d.autoDetect = true
	}
}

// DialContext connects through the selected underlay interface.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.active.Add(1)
	d.mu.Unlock()
	defer d.active.Done()
	if d.lifecycleCtx != nil {
		child, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(d.lifecycleCtx, cancel)
		defer func() { stop(); cancel() }()
		ctx = child
	}
	if err := d.prepareController(ctx, address); err != nil {
		return nil, err
	}
	if isLoopbackAddress(address) {
		connection, err := d.dial(ctx, network, address, "")
		if err != nil {
			return nil, err
		}
		return d.observeConnection(connection), nil
	}
	interfaceName := d.ensureInterface(ctx, address)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	autoDetect := d.autoDetect
	requireBound := d.requireBound
	controllerTunnel := d.controller != nil && d.controller.TunEnabled
	d.mu.RUnlock()
	if d.isTunnel(interfaceName) {
		return nil, mihomo.ErrUnavailable
	}
	if requireBound && interfaceName == "" && (autoDetect || controllerTunnel) {
		interfaceName = d.refreshInterface()
		if interfaceName == "" {
			return nil, fmt.Errorf("no usable underlay interface")
		}
	}

	conn, err := d.dial(ctx, network, address, interfaceName)
	if err == nil {
		return d.observeConnection(conn), nil
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	refreshedInterface := d.refreshInterface()
	if refreshedInterface == "" || refreshedInterface == interfaceName {
		return nil, err
	}

	conn, retryErr := d.dial(ctx, network, address, refreshedInterface)
	if retryErr != nil {
		return nil, fmt.Errorf("dial underlay via %q failed after %q failed: %w", refreshedInterface, interfaceName, retryErr)
	}
	return d.observeConnection(conn), nil
}

func (d *Dialer) ensureInterface(ctx context.Context, address string) string {
	for {
		d.mu.Lock()
		if !d.autoDetect || d.interfaceName != "" {
			name := d.interfaceName
			d.mu.Unlock()
			return name
		}
		if done := d.detecting; done != nil {
			d.mu.Unlock()
			select {
			case <-ctx.Done():
				return ""
			case <-done:
				continue
			}
		}
		done := make(chan struct{})
		d.detecting = done
		d.mu.Unlock()
		return d.detectOnce(ctx, address, done)
	}
}
func (d *Dialer) detectOnce(ctx context.Context, address string, done chan struct{}) (name string) {
	defer func() { d.mu.Lock(); d.detecting = nil; close(done); name = d.interfaceName; d.mu.Unlock() }()
	d.mu.RLock()
	resolver := d.resolver
	source := d.originalSource
	d.mu.RUnlock()
	var detected string
	if source.IsValid() {
		detected = interfaceForSource(source)
	} else {
		detected = detectInterfaceWithResolver(ctx, address, resolver)
	}
	d.mu.Lock()
	if ctx.Err() == nil && usableInterface(detected, d.excludedIPs) && !mihomo.SameInterface(detected, d.tunDevice) {
		d.updateInterfaceName(detected)
	}
	d.mu.Unlock()
	return
}

func (d *Dialer) updateInterfaceName(interfaceName string) {
	if interfaceName == "" || interfaceName == d.interfaceName {
		return
	}
	d.interfaceName = interfaceName

}

func (d *Dialer) observeConnection(conn net.Conn) net.Conn {
	if local, ok := conn.LocalAddr().(interface{ AddrPort() netip.AddrPort }); ok {
		ip := local.AddrPort().Addr().Unmap()
		if ip.IsGlobalUnicast() && !ip.IsLoopback() {
			d.mu.Lock()
			if !d.requireBound && d.interfaceName == "" {
				d.originalSource = ip
			}
			d.mu.Unlock()
		}
	}
	return conn
}

func dialContextOnInterface(ctx context.Context, network, address, interfaceName, localDNSServer string) (net.Conn, error) {
	dialer := &socketdialer.Dialer{InterfaceName: interfaceName, UnboundLoopback: true}
	if interfaceName != "" || localDNSServer != "" {
		dialer.Resolver = newUnderlayResolver(interfaceName, localDNSServer)
	}
	return dialer.DialContext(ctx, network, address)
}

func newUnderlayResolver(interfaceName, localDNSServer string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, systemDNSServer string) (net.Conn, error) {
			target := systemDNSServer
			if localDNSServer != "" {
				target = localDNSServer
			}
			boundInterface := interfaceName
			if isLoopbackAddress(target) {
				boundInterface = ""
			}
			dialer := &socketdialer.Dialer{InterfaceName: boundInterface}
			return dialer.DialContext(ctx, network, target)
		},
	}
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeLocalDNSServer(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	if ip := net.ParseIP(address); ip != nil {
		return net.JoinHostPort(address, "53"), nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return "", fmt.Errorf("local DNS server must be an IP address with an optional port: %q", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid local DNS server port in %q", address)
	}
	return net.JoinHostPort(host, port), nil
}

var dialOnInterface = dialContextOnInterface

func detectInterface(ctx context.Context, targetAddress string) string {
	return detectInterfaceWithResolver(ctx, targetAddress, nil)
}

func detectInterfaceWithResolver(ctx context.Context, targetAddress string, resolver *net.Resolver) string {
	if interfaceName := findDefaultInterface(); usableInterface(interfaceName, nil) {
		return interfaceName
	}

	// This fallback is primarily for platforms without a default-interface
	// monitor. The first DialContext runs before the TUN interface is installed.
	host, port, err := net.SplitHostPort(targetAddress)
	if err != nil {
		host = targetAddress
		port = "443"
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second, Resolver: resolver}).DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	source, ok := netip.AddrFromSlice(localIP)
	if !ok {
		return ""
	}
	return interfaceForSource(source.Unmap())
}

func (d *Dialer) refreshInterface() string {
	d.mu.RLock()
	autoDetect := d.autoDetect
	source := d.originalSource
	d.mu.RUnlock()
	if !autoDetect {
		return ""
	}

	var interfaceName string
	if source.IsValid() {
		interfaceName = interfaceForSource(source)
	} else {
		interfaceName = findDefaultInterface()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !usableInterface(interfaceName, d.excludedIPs) || mihomo.SameInterface(interfaceName, d.tunDevice) {
		return ""
	}
	d.updateInterfaceName(interfaceName)
	return interfaceName
}

var findDefaultInterface = detectDefaultInterface

// The pre-VPN control socket identifies its real exit, including an overlay interface.
func interfaceForSource(source netip.Addr) string {
	interfaces, err := networkstate.Interfaces()
	if err != nil {
		return ""
	}
	var selected string
	for _, iface := range interfaces {
		if !iface.Up || iface.Loopback {
			continue
		}
		for _, address := range iface.Addresses {
			prefix, err := netip.ParsePrefix(address)
			if err == nil && prefix.Addr().Unmap() == source {
				if selected != "" && selected != iface.Name {
					return ""
				}
				selected = iface.Name
			}
		}
	}
	return selected
}

func detectDefaultInterface() string {
	networkMonitor, err := tun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return ""
	}
	if err := networkMonitor.Start(); err != nil {
		_ = networkMonitor.Close()
		return ""
	}
	defer networkMonitor.Close()

	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), tun.DefaultInterfaceMonitorOptions{})
	if err != nil {
		return ""
	}
	if err := interfaceMonitor.Start(); err != nil {
		_ = interfaceMonitor.Close()
		return ""
	}
	defer interfaceMonitor.Close()

	return interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified())
}

func usableInterface(interfaceName string, excludedIPs []net.IP) bool {
	if interfaceName == "" {
		return false
	}
	interfaces, err := networkstate.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Name != interfaceName {
			continue
		}
		if !iface.Up || iface.Loopback {
			return false
		}
		for _, address := range iface.Addresses {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				return false
			}
			for _, excludedIP := range excludedIPs {
				excluded, ok := netip.AddrFromSlice(excludedIP)
				if ok && prefix.Addr().Unmap() == excluded.Unmap() {
					return false
				}
			}
		}
		return true
	}
	return false
}
