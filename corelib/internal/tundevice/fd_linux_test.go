//go:build linux

package tundevice

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
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

func TestNativeLinuxTUNDescriptors(t *testing.T) {
	if os.Getenv("JC_TEST_TUN_NATIVE") != "1" {
		t.Skip("native descriptor checks run in the guarded Linux Core ABI namespace")
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Stat("/proc/1/ns/net")
	if err != nil || os.Geteuid() != 0 || os.SameFile(current, initial) {
		t.Fatal("requires root in a private network namespace")
	}
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err := handle.SetSocketTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		flags   uint16
		persist bool
		valid   bool
	}{
		{"raw", unix.IFF_TUN | unix.IFF_NO_PI, false, true},
		{"pi", unix.IFF_TUN, false, false},
		{"tap", unix.IFF_TAP | unix.IFF_NO_PI, false, false},
		{"virtio", unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR, false, false},
		{"multiqueue", unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE, false, false},
		{"persistent", unix.IFF_TUN | unix.IFF_NO_PI, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			request, _ := unix.NewIfreq("")
			request.SetUint16(test.flags)
			if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
				t.Fatal(err)
			}
			if test.persist {
				if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
					t.Fatal(err)
				}
				defer unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0)
			}
			link, err := handle.LinkByName(request.Name())
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.LinkSetMTU(link, 1400); err != nil {
				t.Fatal(err)
			}
			if err := handle.LinkSetUp(link); err != nil {
				t.Fatal(err)
			}
			device, err := Duplicate(fd, 1400)
			if !test.valid {
				if err == nil {
					device.Close()
					t.Fatal("unsupported kernel framing accepted")
				}
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil {
					t.Fatal("rejected fd was closed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			if int(device.Fd()) == fd {
				t.Fatal("caller fd was adopted instead of duplicated")
			}
			if flags, err := unix.FcntlInt(device.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatal("owned duplicate can leak across exec", err)
			}
			if wrong, err := Duplicate(fd, 1401); err == nil {
				wrong.Close()
				t.Fatal("mismatched device MTU accepted")
			}
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
			device.Close()
			select {
			case err := <-completed:
				if !errors.Is(err, os.ErrClosed) {
					t.Fatal("close did not interrupt packet read", err)
				}
			case <-time.After(time.Second):
				t.Fatal("device close did not join blocked I/O")
			}
			if err := unix.SetNonblock(fd, false); err != nil {
				t.Fatal(err)
			}
			if blocking, err := Duplicate(fd, 1400); err == nil {
				blocking.Close()
				t.Fatal("blocking fd accepted")
			}
			if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatal("rejected fd flags changed", err)
			}
		})
	}
}
