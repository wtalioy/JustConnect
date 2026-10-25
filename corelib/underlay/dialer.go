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
	closeErr       error
	interfaceName  string
	autoDetect     bool
	excludedIPs    []net.IP
	requireBound   bool
	capture        *pcapCapture
	localDNSServer string
}

// Options configures a Dialer.
type Options struct {
	// InterfaceName explicitly selects the interface used by underlay sockets.
	// It takes precedence over AutoDetect.
	InterfaceName string
	AutoDetect    bool
	// DebugPCAPFile records application-visible TCP traffic on underlay sockets.
	DebugPCAPFile string
	// LocalDNSServer overrides the system DNS for VPN server hostname resolution.
	// It must be an IP address with an optional port.
	LocalDNSServer string
}

// New creates an underlay dialer. With no options, interface auto-detection is
// enabled. The caller must close the returned dialer.
func New(options ...Options) (*Dialer, error) {
	option := Options{AutoDetect: true}
	if len(options) > 0 {
		option = options[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{autoDetect: option.AutoDetect, lifecycleCtx: ctx, cancel: cancel}
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
	if option.DebugPCAPFile != "" {
		capture, err := newPCAPCapture(option.DebugPCAPFile)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("initialize underlay PCAP capture: %w", err)
		}
		d.capture = capture
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

// Close flushes and closes the optional packet capture.
func (d *Dialer) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		if d.cancel != nil {
			d.cancel()
		}
		d.mu.Unlock()
		d.active.Wait()
		if d.capture != nil {
			d.closeErr = d.capture.Close()
		}
	})
	return d.closeErr
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
	d.requireBound = true
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
	interfaceName := d.ensureInterface(ctx, address)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.RLock()
	autoDetect := d.autoDetect
	requireBound := d.requireBound
	d.mu.RUnlock()
	if autoDetect && requireBound && interfaceName == "" {
		interfaceName = d.refreshInterface()
		if interfaceName == "" {
			return nil, fmt.Errorf("no usable underlay interface")
		}
	}

	conn, err := dialOnInterface(ctx, network, address, interfaceName, d.localDNSServer)
	if err == nil {
		return d.wrapCapture(conn), nil
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	refreshedInterface := d.refreshInterface()
	if refreshedInterface == "" || refreshedInterface == interfaceName {
		return nil, err
	}

	conn, retryErr := dialOnInterface(ctx, network, address, refreshedInterface, d.localDNSServer)
	if retryErr != nil {
		return nil, fmt.Errorf("dial underlay via %q failed after %q failed: %w", refreshedInterface, interfaceName, retryErr)
	}
	return d.wrapCapture(conn), nil
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
	detected := detectInterface(ctx, address)
	d.mu.Lock()
	if ctx.Err() == nil && usableInterface(detected, d.excludedIPs) {
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

func (d *Dialer) wrapCapture(conn net.Conn) net.Conn {
	if d.capture == nil {
		return conn
	}
	return d.capture.Wrap(conn)
}

func dialContextOnInterface(ctx context.Context, network, address, interfaceName, localDNSServer string) (net.Conn, error) {
	dialer := &socketdialer.Dialer{InterfaceName: interfaceName}
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
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.Equal(localIP) {
				if usableInterface(iface.Name, nil) {
					return iface.Name
				}
				return ""
			}
		}
	}
	return ""
}

func (d *Dialer) refreshInterface() string {
	d.mu.RLock()
	autoDetect := d.autoDetect
	d.mu.RUnlock()
	if !autoDetect {
		return ""
	}

	interfaceName := findDefaultInterface()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !usableInterface(interfaceName, d.excludedIPs) {
		return ""
	}
	d.updateInterfaceName(interfaceName)
	return interfaceName
}

var findDefaultInterface = detectDefaultInterface

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
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if len(excludedIPs) == 0 {
		return true
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		var interfaceIP net.IP
		switch value := address.(type) {
		case *net.IPNet:
			interfaceIP = value.IP
		case *net.IPAddr:
			interfaceIP = value.IP
		}
		for _, excludedIP := range excludedIPs {
			if interfaceIP != nil && interfaceIP.Equal(excludedIP) {
				return false
			}
		}
	}
	return true
}
