package corelib

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/privatefile"
	"github.com/wtalioy/JustConnect/corelib/underlay"
)

func TestSessionPanicClosesOwnedDebugFiles(t *testing.T) {
	directory := t.TempDir()
	keyLog, capture := filepath.Join(directory, "tls.log"), filepath.Join(directory, "traffic.pcap")
	options := Options{Setup: atrust.SetupOptions{ServerAddress: "127.0.0.1", ServerPort: 443}, TLSKeyLogFile: keyLog,
		Underlay: underlay.Options{DebugPCAPFile: capture}, Client: atrust.ClientOptions{Diagnostic: func(string) { panic("private credentials") }}}
	err := NewSession(options).Run(context.Background(), Observer{})
	if err == nil || err.Error() != "core_session_panicked" {
		t.Fatalf("panic error = %v", err)
	}
	if entries, readErr := os.ReadDir("/proc/self/fd"); readErr == nil {
		for _, entry := range entries {
			target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if target == keyLog || target == capture {
				t.Fatalf("owned descriptor remained open: %s", target)
			}
		}
	}
	for _, path := range []string{keyLog, capture} {
		file, err := privatefile.Open(path)
		if err != nil {
			t.Fatalf("owned file remained open: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}
