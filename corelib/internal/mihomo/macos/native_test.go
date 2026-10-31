//go:build darwin

package macos

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/unix"
)

func TestUnixListenersPreserveOwnedPathsAndExcludeConnections(t *testing.T) {
	data := `Active LOCAL (UNIX) domain sockets
Address Type Recv-Q Send-Q Inode Conn Refs Nextref rxbytes txbytes rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs Addr
aa stream 0 0 bb 0 0 0 0 0 8192 8192 mihomo:123 00000 00000000 0000000000000000 00000000 00000000 1 1 000000 /private/tmp/actual controller.sock
cc stream 0 0 dd 12 0 0 0 0 8192 8192 mihomo:123 00000 00000000 0000000000000000 00000000 00000000 1 1 000000 /private/tmp/connected.sock
ee dgram 0 0 ff 0 0 0 0 0 8192 8192 mihomo:123 00000 00000000 0000000000000000 00000000 00000000 1 1 000000 /private/tmp/datagram.sock
11 stream 0 0 22 0 0 0 0 0 8192 8192 other:456 00000 00000000 0000000000000000 00000000 00000000 1 1 000000 /private/tmp/unowned.sock
33 stream 0 0 44 0 0 0 0 0 8192 8192 mihomo:123 00000 00000000 0000000000000000 00000000 00000000 1 1 000000 /private/tmp/actual controller.sock
`
	got, err := unixListeners(strings.NewReader(data), map[int]bool{123: true})
	if err != nil || len(got) != 1 || !slices.Equal(got[123], []string{"/private/tmp/actual controller.sock"}) {
		t.Fatalf("unexpected owned Unix listeners: %v %v", got, err)
	}
	if _, err := unixListeners(strings.NewReader("Address Type Conn Addr\n"), map[int]bool{123: true}); err == nil {
		t.Fatal("socket inventory without PID ownership was accepted")
	}
}

func TestNativeSocketInventoryContainsActualListener(t *testing.T) {
	directory, err := os.MkdirTemp("", "jcm-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	owned, err := observedIPC(t.Context(), map[int]bool{os.Getpid(): true})
	if err != nil || !slices.Contains(owned[os.Getpid()], path) {
		t.Fatalf("actual Unix listener disappeared from native PID inventory: %v", err)
	}
}

func TestCommandOutputIsBoundedAndCancelable(t *testing.T) {
	if _, err := commandOutput(t.Context(), "/usr/bin/yes"); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("unbounded native output was accepted", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := commandOutput(ctx, "/bin/sleep", "10"); err == nil || time.Since(started) > time.Second {
		t.Fatal("canceled native read retained its child process", err)
	}
}

func TestNativeTCPListenerOwnershipTracksActualSocket(t *testing.T) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	process := model.Process{PID: os.Getpid(), Started: stamp(info)}
	for _, host := range []string{"127.0.0.1", "::1"} {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		target := netip.MustParseAddrPort(listener.Addr().String())
		owned := OwnsTCP(t.Context(), process, target)
		listener.Close()
		if !owned || OwnsTCP(t.Context(), process, target) {
			t.Fatalf("native %s ownership did not track the actual listening socket", host)
		}
	}
}

func BenchmarkNativeTCPOwnership(b *testing.B) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		b.Fatal(err)
	}
	process := model.Process{PID: os.Getpid(), Started: stamp(info)}
	target := netip.MustParseAddrPort(listener.Addr().String())
	b.Run("previous_lsof_inventory", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ctx, cancel := context.WithTimeout(b.Context(), 3*time.Second)
			output, err := commandOutput(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(process.PID), "-iTCP", "-sTCP:LISTEN", "-Fftn")
			cancel()
			if err != nil || !strings.Contains(string(output), target.String()) {
				b.Fatal("lsof inventory lost the actual listener", err)
			}
		}
	})
	b.Run("native_pid_tcp_inventory", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !OwnsTCP(b.Context(), process, target) {
				b.Fatal("native PID inventory lost the actual listener")
			}
		}
	})
}
