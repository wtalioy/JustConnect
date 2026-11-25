//go:build linux

package tun

import (
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Unsupported frames must be dropped without ending the shared read loop: the
// next valid IPv4 packet still gets through, and a real I/O error (EOF) still
// surfaces.
func TestReadDropsUnsupportedPacketsAndKeepsReading(t *testing.T) {
	// A SEQPACKET socketpair stands in for the TUN queue: every send is
	// exactly one frame and every read returns exactly one frame.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	writer := os.NewFile(uintptr(fds[0]), "tun-writer")
	reader := os.NewFile(uintptr(fds[1]), "tun-reader")
	device := &Device{File: reader}

	// An IPv6 frame, a truncated frame and a non-IP frame all precede the one
	// valid IPv4 packet.
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	for _, frame := range [][]byte{ipv6, {0x45, 0x00, 0x00}, []byte("not an IP frame at all")} {
		if _, err := writer.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	valid := make([]byte, 20)
	valid[0] = 0x45 // IPv4, IHL 5
	if _, err := writer.Write(valid); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 2048)
	n, err := device.Read(buffer)
	if err != nil {
		t.Fatalf("the valid packet was lost after unsupported frames: %v", err)
	}
	if n != 20 || buffer[0]>>4 != 4 {
		t.Fatalf("unexpected packet: n=%d version=%d", n, buffer[0]>>4)
	}

	// The loop must still end on a real error instead of swallowing reads.
	if _, err := device.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF once the queue drained, got %v", err)
	}
}
