//go:build linux

package linux

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseProcStatReadsNameAndStartTime(t *testing.T) {
	header := "987 (custom (proxy)\nname) S" + strings.Repeat(" 0", 18)
	name, started, err := parseProcStat([]byte(header + " 123456789 42\n"))
	if err != nil || string(name) != "custom (proxy)\nname" || started != 123456789 {
		t.Fatalf("parseProcStat() = %q, %d, %v", name, started, err)
	}
	for _, malformed := range []string{
		"987 (missing terminator",
		header,
		header + " invalid 42",
	} {
		if _, _, err := parseProcStat([]byte(malformed)); err == nil {
			t.Fatalf("accepted malformed stat %q", malformed)
		}
	}
}

func TestObservedIPCFindsOwnedStreamListener(t *testing.T) {
	directory, err := os.MkdirTemp("", "jc-unix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	streamPath := filepath.Join(directory, "control socket ")
	stream, err := net.Listen("unix", streamPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	datagramPath := filepath.Join(directory, "datagram")
	datagram, err := net.ListenPacket("unixgram", datagramPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { datagram.Close() })

	paths := observedIPC(os.Getpid())
	if !slices.Contains(paths, streamPath) || slices.Contains(paths, datagramPath) {
		t.Fatalf("own stream listener missing or datagram accepted: %q", paths)
	}
}
