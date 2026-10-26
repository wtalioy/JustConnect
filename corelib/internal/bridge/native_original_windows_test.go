//go:build windows

package bridge

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/packetpipe"
	nativepipe "github.com/wtalioy/JustConnect/corelib/internal/packetpipe/windows"
	"golang.org/x/sys/windows"
)

func startWindowsOriginalPeer(t *testing.T, gateway *gateway) *nativeOriginalPeer {
	t.Helper()
	native, dll := os.Getenv("JC_TEST_CPP_WINTUN_BROKER"), os.Getenv("JC_TEST_WINTUN_DLL")
	if os.Getenv("GITHUB_ACTIONS") != "true" || !windows.GetCurrentProcessToken().IsElevated() || !filepath.IsAbs(native) || !filepath.IsAbs(dll) {
		t.Fatal("original network requires the built C++ broker, verified SDK and elevated disposable runner")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil || prefix.Contains(netip.MustParseAddr("192.0.2.1")) || prefix.Contains(netip.MustParseAddr("198.18.0.6")) {
				t.Fatalf("original fixture address already in use or unreadable: %s", value)
			}
		}
	}
	owner, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name := `\\.\pipe\JustConnect-native-packets-` + owner.String() + "-"
	helper := exec.Command(native, "--original-peer", dll, name)
	helper.Stdin = bytes.NewBufferString(fmt.Sprintf("%d\n", os.Getpid()))
	var output bytes.Buffer
	helper.Stdout, helper.Stderr = &output, &output
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("original C++ device cleanup: %v\n%s", err, output.Bytes())
			}
		case <-time.After(5 * time.Second):
			_ = helper.Process.Kill()
			<-done
			t.Errorf("original C++ device did not release within deadline\n%s", output.Bytes())
		}
	})
	path, err := windows.UTF16PtrFromString(name + "0")
	if err != nil {
		t.Fatal(err)
	}
	var handle windows.Handle
	deadline := time.Now().Add(5 * time.Second)
	for {
		handle, err = windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if (err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PIPE_BUSY) || !time.Now().Before(deadline) {
			t.Fatalf("connect original C++ relay: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stream, err := nativepipe.Duplicate(uint64(handle), uint32(helper.Process.Pid))
	_ = windows.CloseHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		stream.Close()
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(stream, ready[:]); err != nil || ready[0] != 1 {
		stream.Close()
		t.Fatalf("original device allocation: %v, ready=%d", err, ready[0])
	}
	device, err := packetpipe.New(stream, 1400, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	if err != nil {
		stream.Close()
		t.Fatal(err)
	}
	return serveNativeOriginalPeer(t, gateway, device, nil)
}
