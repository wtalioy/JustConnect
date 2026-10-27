//go:build darwin

package macos

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
