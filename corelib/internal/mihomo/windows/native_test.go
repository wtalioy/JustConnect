//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/windows"
)

func TestBusyControllerPipeHonorsCancellation(t *testing.T) {
	name := `\\.\pipe\jcm-busy-` + rand.Text()
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(server)
	occupied, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(occupied)
	process := model.Process{PID: os.Getpid(), Started: creation(windows.CurrentProcess())}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	connection, err := DialIPC(ctx, process, name)
	if connection != nil {
		connection.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("busy pipe did not wait within its cancellation budget: %v", err)
	}
}

func TestNativeTCPListenerOwnershipTracksActualSocket(t *testing.T) {
	process := model.Process{PID: os.Getpid(), Started: creation(windows.CurrentProcess())}
	for _, host := range []string{"127.0.0.1", "::1"} {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		target := netip.MustParseAddrPort(listener.Addr().String())
		owned := OwnsTCP(t.Context(), process, target)
		listener.Close()
		if !owned || OwnsTCP(t.Context(), process, target) {
			t.Fatalf("native %s ownership did not track the listening socket", host)
		}
	}
	if OwnsTCP(t.Context(), process, netip.AddrPort{}) || OwnsTCP(t.Context(), model.Process{}, netip.MustParseAddrPort("127.0.0.1:1")) {
		t.Fatal("invalid endpoint or process was accepted")
	}
}

func TestFilterTCPListenersKeepsOnlyLiveEndpointsOfTheProcess(t *testing.T) {
	process := model.Process{PID: os.Getpid(), Started: creation(windows.CurrentProcess())}
	first := listenTCP(t, "::1")
	second := listenTCP(t, "127.0.0.1")
	ipv6 := netip.MustParseAddrPort(first.Addr().String())
	ipv4 := netip.MustParseAddrPort(second.Addr().String())
	unowned := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), ipv4.Port())
	targets := []netip.AddrPort{ipv6, unowned, {}, ipv4}
	if got := FilterTCPListeners(t.Context(), process, slices.Clone(targets)); !slices.Equal(got, []netip.AddrPort{ipv6, ipv4}) {
		t.Fatal("invalid endpoint accepted or listener order changed", got)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if got := FilterTCPListeners(t.Context(), process, slices.Clone(targets)); !slices.Equal(got, []netip.AddrPort{ipv4}) {
		t.Fatal("fresh observation did not reflect the closed socket", got)
	}
	process.Started++
	if got := FilterTCPListeners(t.Context(), process, targets); len(got) != 0 {
		t.Fatal("stale process identity acquired listener ownership", got)
	}
}

func listenTCP(t testing.TB, host string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func BenchmarkTCPListenerObservation(b *testing.B) {
	process := model.Process{PID: os.Getpid(), Started: creation(windows.CurrentProcess())}
	var targets [6]netip.AddrPort
	for i := range targets {
		host := "127.0.0.1"
		if i%2 != 0 {
			host = "::1"
		}
		targets[i] = netip.MustParseAddrPort(listenTCP(b, host).Addr().String())
	}
	b.Run("separate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, target := range targets {
				if !OwnsTCP(b.Context(), process, target) {
					b.Fatal("actual listener not verified")
				}
			}
		}
	})
	b.Run("grouped", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst := targets
			if len(FilterTCPListeners(b.Context(), process, dst[:])) != len(targets) {
				b.Fatal("actual listeners not verified")
			}
		}
	})
}
