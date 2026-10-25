package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/packetpipe"
	"github.com/wtalioy/JustConnect/corelib/internal/windowstest"
	"github.com/wtalioy/JustConnect/corelib/internal/wintun"
	"golang.org/x/sys/windows"
)

func serveNativeWindowsPackets(ctx context.Context, name, dll string, pid <-chan uint32) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + user.User.Sid.String() + ")S:(ML;;NW;;;ME)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	pipe, err := windows.CreateNamedPipe(windows.StringToUTF16Ptr(name), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes)
	if err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = windows.CloseHandle(pipe)
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	operation := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(pipe, &operation)
	if err == windows.ERROR_IO_PENDING {
		cancel := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(pipe, &operation) })
		var done uint32
		err = windows.GetOverlappedResult(pipe, &operation, &done, true)
		cancel()
	} else if err == windows.ERROR_PIPE_CONNECTED {
		err = nil
	}
	if err != nil {
		return err
	}
	var clientPID uint32
	if err = windows.GetNamedPipeClientProcessId(pipe, &clientPID); err != nil {
		return err
	}
	var expected uint32
	select {
	case expected = <-pid:
	case <-ctx.Done():
		return ctx.Err()
	}
	if clientPID != expected {
		return errors.New("native fixture accepted an unexpected process")
	}
	stream, err := packetpipe.OwnNative(pipe)
	if err != nil {
		return err
	}
	transferred = true
	defer stream.Close()
	cancel := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer cancel()
	var ready [1]byte
	if _, err = io.ReadFull(stream, ready[:]); err != nil || ready[0] != 1 {
		return errors.Join(err, errors.New("core did not request actual adapter allocation"))
	}
	owner, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	local, peer := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	device, err := wintun.Create(dll, owner, local, peer, 1400, []netip.Prefix{netip.MustParsePrefix("198.18.0.6/32")}, func(identity wintun.Identity) error {
		if identity.LUID == 0 || identity.Index == 0 || identity.GUID != owner {
			return errors.New("native adapter allocation did not confirm its owner")
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer device.Close()
	if _, err = stream.Write([]byte{1}); err != nil {
		return err
	}
	transport, err := packetpipe.New(stream, 1400, local, peer)
	if err != nil {
		return err
	}
	var workers sync.WaitGroup
	done := make(chan error, 2)
	for _, direction := range [][2]io.ReadWriteCloser{{device, transport}, {transport, device}} {
		workers.Go(func() {
			packet := make([]byte, 1400)
			for {
				n, err := direction[0].Read(packet)
				if err == nil {
					_, err = direction[1].Write(packet[:n])
				}
				if err != nil {
					done <- err
					return
				}
			}
		})
	}
	err = <-done
	_ = transport.Close()
	_ = device.Close()
	workers.Wait()
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("native packet relay: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		row := windows.MibIfRow2{InterfaceLuid: device.LUID}
		err = windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row)
		if err == windows.ERROR_NOT_FOUND || err == windows.ERROR_FILE_NOT_FOUND {
			return nil
		}
		if err != nil {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("native Wintun owner survived disconnect")
}

func TestNativeWindowsPacketHost(t *testing.T) {
	host := os.Getenv("JC_NATIVE_WINDOWS_PACKET_HOST")
	if host == "" {
		t.Skip("Windows Qt/Wintun packet integration runs in the native ABI target")
	}
	dll := os.Getenv("JC_TEST_WINTUN_DLL")
	if os.Getenv("GITHUB_ACTIONS") != "true" || !windows.GetCurrentProcessToken().IsElevated() || !filepath.IsAbs(dll) {
		t.Fatal("requires the verified SDK and an elevated disposable Windows runner")
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
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				t.Fatal(err)
			}
			if prefix.Contains(netip.MustParseAddr("198.18.0.1")) || prefix.Contains(netip.MustParseAddr("198.18.0.6")) {
				t.Fatal("test addresses already belong to an existing interface")
			}
		}
	}
	token, err := windowstest.OrdinaryToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	g := newGateway(t)
	g.resourceIP.Store("198.18.0.6")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	owner, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	name := `\\.\pipe\JustConnect-native-packets-` + owner.String() + "-"
	identities := make(chan uint32, 2)
	served := make(chan error, 1)
	go func() {
		for round := range 2 {
			if err := serveNativeWindowsPackets(ctx, name+strconv.Itoa(round), dll, identities); err != nil {
				served <- err
				cancel()
				return
			}
		}
		served <- nil
	}()
	command := exec.CommandContext(ctx, host, "--packet-gateway", string(configBytes(t, g.config(t))), name, strconv.FormatUint(uint64(windows.GetCurrentProcessId()), 10))
	command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	for range 2 {
		identities <- uint32(command.Process.Pid)
	}
	err = command.Wait()
	if err != nil {
		cancel()
	}
	serverErr := <-served
	if err != nil || serverErr != nil {
		t.Fatalf("actual native Windows packet chain: host=%v helper=%v\n%s", err, serverErr, output.Bytes())
	}
	if g.authCount.Load() != 2 || g.tcpCount.Load() != 2 || g.udpCount.Load() != 4 {
		t.Fatalf("actual Windows exchanges auth=%d TCP=%d UDP=%d\n%s", g.authCount.Load(), g.tcpCount.Load(), g.udpCount.Load(), output.Bytes())
	}
	t.Log(output.String())
}
