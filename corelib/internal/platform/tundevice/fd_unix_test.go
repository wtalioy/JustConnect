//go:build linux || darwin

package tundevice

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestDuplicateRejectsUnrelatedFilesWithoutConsumingThem(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "caller-owned")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("caller-data"); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(int(file.Fd()), true); err != nil {
		t.Fatal(err)
	}
	before, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if device, err := Duplicate(int(file.Fd()), 1400); err == nil {
		device.Close()
		t.Fatal("regular file accepted as TUN")
	}
	after, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || after != before {
		t.Fatal("rejected file lost its flags or ownership", err)
	}
	if _, err := file.WriteString("-retained"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil || string(data) != "caller-data-retained" {
		t.Fatalf("rejected file content or position changed: %q %v", data, err)
	}
	if device, err := Duplicate(-1, 1400); err == nil {
		device.Close()
		t.Fatal("invalid fd accepted")
	}
}
