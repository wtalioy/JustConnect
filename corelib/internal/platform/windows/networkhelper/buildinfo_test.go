//go:build windows

package networkhelper

import (
	"debug/buildinfo"
	"os"
	"runtime/debug"
	"testing"
)

func TestRunningImageIdentity(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	actual, err := buildinfo.Read(file)
	running, ok := debug.ReadBuildInfo()
	if err != nil || !ok || running.String() != actual.String() {
		t.Fatalf("running identity differs from pinned image: %v\nrunning=%s\nstored=%s", err, running, actual)
	}
}
