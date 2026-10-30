package privatefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenWritesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte("old data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	line := "owned private fixture content\n"
	if _, err := file.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != line {
		t.Fatalf("private content = %q, want %q", data, line)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows FileMode reports the read-only attribute, not ACL permissions.
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("private-file permissions = %o, want 600", got)
	}
}

func TestOpenReportsError(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing", "identity"))
	if err == nil {
		t.Fatal("Open succeeded for a missing parent directory")
	}
}
