package underlay

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

type sourceConnection struct {
	net.Conn
	source *net.TCPAddr
}

func (c sourceConnection) LocalAddr() net.Addr { return c.source }

func TestVPNAddressRetainsObservedExitInsteadOfGuessingDefault(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var original string
	var source net.IP
	virtual := net.IPv4(198, 18, 0, 1)
	for _, iface := range interfaces {
		if !usableInterface(iface.Name, nil) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.Equal(virtual) {
				original, source = iface.Name, ip
				break
			}
		}
		if source != nil {
			break
		}
	}
	if source == nil {
		t.Skip("no original IPv4 source")
	}
	find, dial := findDefaultInterface, dialOnInterface
	t.Cleanup(func() { findDefaultInterface, dialOnInterface = find, dial })
	findDefaultInterface = func() string { t.Error("observed control source was replaced by a default guess"); return "" }
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "observed", true: "source-disappeared"}[missing], func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			local := source
			if missing {
				local = net.IPv4(192, 0, 2, 254)
				if interfaceForSource(netip.MustParseAddr(local.String())) != "" {
					t.Skip("documentation source is already assigned")
				}
			}
			calls := 0
			dialOnInterface = func(_ context.Context, _, _, selected, _ string) (net.Conn, error) {
				if (calls == 0 && selected != "") || (calls > 0 && selected != original) {
					t.Error("control lost its observed original interface", calls, selected)
				}
				calls++
				return sourceConnection{client, &net.TCPAddr{IP: local, Port: 12345}}, nil
			}
			d, err := New(Options{AutoDetect: false, LocalDNSServer: "127.0.0.1:53"})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.10:443"); err != nil {
				t.Fatal(err)
			}
			d.ExcludeIP(virtual)
			_, err = d.DialContext(t.Context(), "tcp", "192.0.2.10:443")
			if missing {
				if err == nil || calls != 1 {
					t.Fatal("disappeared source reached a replacement interface", err, calls)
				}
			} else if err != nil || calls != 2 || d.InterfaceName() != original {
				t.Fatal("observed source did not survive VPN capture", err, calls)
			}
		})
	}
}

func TestVPNAddressRequiresBoundControlWithDefaultOptions(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	virtual := net.IPv4(198, 18, 0, 1)
	var original string
	for _, iface := range interfaces {
		if usableInterface(iface.Name, []net.IP{virtual}) {
			original = iface.Name
			break
		}
	}
	if original == "" {
		t.Skip("no original interface available")
	}
	find, dial := findDefaultInterface, dialOnInterface
	t.Cleanup(func() { findDefaultInterface, dialOnInterface = find, dial })
	findDefaultInterface = func() string { return original }
	for _, manual := range []string{"", original} {
		t.Run(manual, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			dialOnInterface = func(_ context.Context, _, _, selected, _ string) (net.Conn, error) {
				if selected != original {
					t.Errorf("VPN control remained unbound after virtual address exclusion: %q", selected)
				}
				return client, nil
			}
			d, err := New(Options{AutoDetect: false, InterfaceName: manual, LocalDNSServer: "127.0.0.1:53"})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.ExcludeIP(virtual)
			if _, err := d.DialContext(t.Context(), "tcp", "192.0.2.10:443"); err != nil {
				t.Fatal(err)
			}
			if d.InterfaceName() != original {
				t.Fatal("control did not retain its original interface")
			}
		})
	}
}

func TestVPNAddressCannotBecomeItsOwnOriginalExit(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	find, dial := findDefaultInterface, dialOnInterface
	t.Cleanup(func() { findDefaultInterface, dialOnInterface = find, dial })
	for _, iface := range interfaces {
		if !usableInterface(iface.Name, nil) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			findDefaultInterface = func() string { return iface.Name }
			dialOnInterface = func(context.Context, string, string, string, string) (net.Conn, error) {
				t.Error("excluded VPN interface reached a destination dial")
				return nil, net.ErrClosed
			}
			d, err := New(Options{AutoDetect: false, LocalDNSServer: "127.0.0.1:53"})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.ExcludeIP(ip)
			if connection, err := d.DialContext(t.Context(), "tcp", "192.0.2.10:443"); err == nil {
				connection.Close()
				t.Fatal("unavailable original exit silently fell back")
			}
			return
		}
	}
	t.Skip("no addressed original interface available")
}

func TestVPNAddressKeepsLoopbackLocalWithoutAnOriginalExit(t *testing.T) {
	find, dial := findDefaultInterface, dialOnInterface
	t.Cleanup(func() { findDefaultInterface, dialOnInterface = find, dial })
	findDefaultInterface = func() string { t.Error("loopback queried an original exit"); return "" }
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	dialOnInterface = func(_ context.Context, _, _, selected, _ string) (net.Conn, error) {
		if selected != "" {
			t.Error("loopback acquired an interface binding", selected)
		}
		return client, nil
	}
	d, err := New(Options{AutoDetect: false, LocalDNSServer: "127.0.0.1:53"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.ExcludeIP(net.IPv4(198, 18, 0, 1))
	for _, address := range []string{"127.0.0.1:443", "[::1]:443"} {
		if _, err := d.DialContext(t.Context(), "tcp", address); err != nil {
			t.Fatal("loopback control depended on an external exit", err)
		}
	}
}
