//go:build darwin

package utun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUTUNFramingAndClose(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	device := &Device{File: os.NewFile(uintptr(fds[0]), "framing-test")}
	defer device.Close()
	if rejected, err := Duplicate(fds[0], 1400); err == nil {
		rejected.Close()
		t.Fatal("Unix socket accepted as utun")
	}
	frame := func(family uint32, payload []byte) []byte {
		result := make([]byte, 4, 4+len(payload))
		binary.BigEndian.PutUint32(result, family)
		return append(result, payload...)
	}
	packet := make([]byte, 20)
	packet[0] = 0x45
	for _, test := range []struct {
		name  string
		wire  []byte
		size  int
		valid bool
	}{
		{"ipv4", frame(unix.AF_INET, packet), 1400, true},
		{"short-header", []byte{0, 0}, 1400, false},
		{"wrong-family", frame(unix.AF_UNIX, packet), 1400, false},
		{"wrong-version", frame(unix.AF_INET, make([]byte, 20)), 1400, false},
		{"truncated", frame(unix.AF_INET, packet), 19, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := unix.Write(fds[1], frame(unix.AF_INET6, make([]byte, 40))); err != nil {
				t.Fatal(err)
			}
			if _, err := unix.Write(fds[1], test.wire); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, test.size)
			n, err := device.Read(buffer)
			if test.valid {
				if err != nil || !bytes.Equal(buffer[:n], packet) {
					t.Fatalf("IPv4 packet = %x, %v", buffer[:n], err)
				}
			} else if !errors.Is(err, unix.EINVAL) {
				t.Fatalf("invalid frame accepted: n=%d err=%v", n, err)
			}
		})
	}
	if n, err := device.Write(packet); err != nil || n != len(packet) {
		t.Fatal(n, err)
	}
	buffer := make([]byte, 1404)
	if n, err := unix.Read(fds[1], buffer); err != nil || !bytes.Equal(buffer[:n], frame(unix.AF_INET, packet)) {
		t.Fatalf("outbound framing = %x, %v", buffer[:n], err)
	}
	if _, err := device.Write(make([]byte, 20)); !errors.Is(err, unix.EINVAL) {
		t.Fatal("invalid outbound IPv4 accepted", err)
	}
	checkReadClose(t, device)
	if _, err := device.Write(packet); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed device write lost its close status", err)
	}
}

func checkReadClose(t *testing.T, device *Device) {
	t.Helper()
	completed := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1401)
		for {
			if _, err := device.Read(buffer); err != nil {
				completed <- err
				return
			}
		}
	}()
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatal("close did not interrupt packet read", err)
		}
	case <-time.After(time.Second):
		t.Fatal("device close did not join blocked I/O")
	}
}

func TestNativeDarwinTUNDescriptors(t *testing.T) {
	inherited := os.Getenv("JC_TEST_TUN_FD")
	if inherited == "" {
		t.Skip("native descriptor check requires the disposable macOS runner fixture")
	}
	fd, err := strconv.Atoi(inherited)
	if err != nil || fd < 3 || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("requires an ordinary caller and borrowed utun fd")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	device, err := Duplicate(fd, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if local, peer := device.TUNAddresses(); local != netip.MustParseAddr("198.18.0.1") || peer != netip.MustParseAddr("198.18.0.2") {
		t.Fatal("kernel TUN addresses differ", local, peer)
	}
	if int(device.Fd()) == fd {
		t.Fatal("caller fd adopted instead of duplicated")
	}
	if value, err := unix.FcntlInt(device.Fd(), unix.F_GETFD, 0); err != nil || value&unix.FD_CLOEXEC == 0 {
		t.Fatal("duplicate can leak across exec", err)
	}
	if wrong, err := Duplicate(fd, 1401); err == nil {
		wrong.Close()
		t.Fatal("mismatched MTU accepted")
	}
	checkReadClose(t, device)
	if value, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil || value != flags {
		t.Fatal("caller fd closed or flags changed", err)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	defer unix.SetNonblock(fd, true)
	if blocking, err := Duplicate(fd, 1400); err == nil {
		blocking.Close()
		t.Fatal("blocking fd accepted")
	}
	if value, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil || value&unix.O_NONBLOCK != 0 {
		t.Fatal("rejected fd flags changed", err)
	}
}
