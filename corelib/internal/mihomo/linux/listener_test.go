//go:build linux

package linux

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

func BenchmarkListenerOwnership(b *testing.B) {
	// Keep 128 unrelated descriptors ahead of the listener, as in a busy proxy process.
	for range 128 {
		file, err := os.Open("/dev/null")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { file.Close() })
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	target := netip.MustParseAddrPort(listener.Addr().String())
	process := model.Process{PID: os.Getpid(), Started: started(os.Getpid())}
	inode := OwnedListenerInode(b.Context(), process, target)
	if inode == 0 {
		b.Fatal("the real listener was not attested")
	}
	b.Run("fd_table", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !OwnsTCP(b.Context(), process, target) {
				b.Fatal("listener changed")
			}
		}
	})
	b.Run("cached_inode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !ListenerUnchanged(b.Context(), process, target, inode) {
				b.Fatal("listener changed")
			}
		}
	})
}
