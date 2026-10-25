//go:build !windows

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRestrictsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	if err := os.WriteFile(path, []byte("old secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() != 0 {
		t.Fatalf("private output has mode %o and size %d", info.Mode().Perm(), info.Size())
	}
}
