//go:build windows

package windows

import (
	"context"
	"os"
	"strings"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/windows"
)

// SystemProcessInformation exposes creation times without opening protected service processes.
func processTimes(ctx context.Context) (map[uint32]uint64, error) {
	for size := uint32(64 << 10); size <= 16<<20; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		buffer := make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&buffer[0]), size, &needed)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH {
			size = max(size*2, needed)
			continue
		}
		if err != nil {
			return nil, err
		}
		if needed > size {
			return nil, os.ErrInvalid
		}
		return decodeProcessTimes(buffer[:needed])
	}
	return nil, os.ErrInvalid
}

func decodeProcessTimes(buffer []byte) (map[uint32]uint64, error) {
	width := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	times := make(map[uint32]uint64)
	for at := 0; ; {
		if len(buffer)-at < width {
			return nil, os.ErrInvalid
		}
		entry := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[at]))
		if entry.UniqueProcessID > 0 && entry.UniqueProcessID <= 1<<32-1 && entry.CreateTime > 0 {
			times[uint32(entry.UniqueProcessID)] = uint64(entry.CreateTime)
		}
		if entry.NextEntryOffset == 0 {
			return times, nil
		}
		next := uint64(entry.NextEntryOffset)
		if next < uint64(width) || next > uint64(len(buffer)-at) || next%uint64(unsafe.Alignof(*entry)) != 0 {
			return nil, os.ErrInvalid
		}
		at += int(next)
	}
}

// This is Verge's public controller namespace, not its privileged service channel:
// github.com/clash-verge-rev/clash-verge-service-ipc/blob/v2.7.6/src/core/paths.rs
// shortcut: other protected IPC namespaces require a public discovery contract before support.
const vergeControllerPrefix = "verge-mihomo-"

func observeControllerPipes(ctx context.Context, processes []model.Process) ([]model.Process, error) {
	if len(processes) == 0 {
		return processes, ctx.Err()
	}
	pattern, _ := windows.UTF16PtrFromString(`\\.\pipe\*`)
	var entry windows.Win32finddata
	search, err := windows.FindFirstFile(pattern, &entry)
	if err == windows.ERROR_FILE_NOT_FOUND {
		return processes, nil
	}
	if err != nil {
		return nil, err
	}
	defer windows.FindClose(search)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := windows.UTF16ToString(entry.FileName[:])
		if strings.HasPrefix(strings.ToLower(name), vergeControllerPrefix) {
			address := `\\.\pipe\` + name
			path, pathErr := windows.UTF16PtrFromString(address)
			if pathErr != nil {
				return nil, pathErr
			}
			// Opening a pipe connects to it, so never probe unrelated system channels.
			handle, openErr := windows.CreateFile(path, 0, 0, nil, windows.OPEN_EXISTING,
				windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
			if openErr == nil {
				var pid uint32
				ownerErr := windows.GetNamedPipeServerProcessId(handle, &pid)
				windows.CloseHandle(handle)
				if ownerErr == nil {
					for i := range processes {
						if processes[i].PID == int(pid) && Valid(processes[i]) {
							processes[i].IPC = append(processes[i].IPC, address)
						}
					}
				}
			}
		}
		err = windows.FindNextFile(search, &entry)
		if err == windows.ERROR_NO_MORE_FILES {
			return processes, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
	}
}
