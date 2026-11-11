//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"testing"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/windows"
)

func TestPublicProcessCreationIdentity(t *testing.T) {
	times, err := processTimes(t.Context())
	if err != nil || times[uint32(os.Getpid())] != creation(windows.CurrentProcess()) {
		t.Fatal("public creation time differs from the actual process handle", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := processTimes(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled process query", err)
	}
}

func TestMalformedProcessTablePublishesNoIdentities(t *testing.T) {
	width := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	for _, next := range []uint32{1, uint32(width + 1), uint32(width * 3)} {
		buffer := make([]byte, width*2)
		entry := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[0]))
		entry.UniqueProcessID, entry.CreateTime, entry.NextEntryOffset = 1234, 5678, next
		if result, err := decodeProcessTimes(buffer); err == nil || result != nil {
			t.Fatal("partial or malformed process table acquired identity", next)
		}
	}
	if _, err := decodeProcessTimes(make([]byte, width-1)); err == nil {
		t.Fatal("truncated process table accepted")
	}
}

func pendingControllerPipe(t *testing.T, name string) (windows.Handle, *windows.Overlapped) {
	t.Helper()
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(server)
		t.Fatal(err)
	}
	operation := &windows.Overlapped{HEvent: event}
	if err := windows.ConnectNamedPipe(server, operation); err != windows.ERROR_IO_PENDING {
		windows.CloseHandle(event)
		windows.CloseHandle(server)
		t.Fatal("pipe accept was not pending", err)
	}
	t.Cleanup(func() {
		windows.CancelIoEx(server, operation)
		var count uint32
		windows.GetOverlappedResult(server, operation, &count, true)
		windows.CloseHandle(event)
		windows.CloseHandle(server)
	})
	return server, operation
}

func TestObservedControllerPipeRejectsReusedPIDAndLeavesOtherChannelsUntouched(t *testing.T) {
	unrelated, accept := pendingControllerPipe(t, `\\.\pipe\jcm-private-channel-`+rand.Text())
	for _, stale := range []bool{false, true} {
		name := `\\.\pipe\verge-mihomo-test-` + rand.Text()
		pendingControllerPipe(t, name)
		process := model.Process{PID: os.Getpid(), Started: creation(windows.CurrentProcess())}
		if stale {
			process.Started++
		}
		result, err := observeControllerPipes(t.Context(), []model.Process{process})
		if err != nil || len(result) != 1 || slices.Contains(result[0].IPC, name) == stale {
			t.Fatal("observed pipe did not enforce PID creation identity", stale, err)
		}
	}
	var count uint32
	if err := windows.GetOverlappedResult(unrelated, accept, &count, false); err != windows.ERROR_IO_INCOMPLETE {
		t.Fatal("unrelated single-client channel was consumed by discovery", err)
	}
}
