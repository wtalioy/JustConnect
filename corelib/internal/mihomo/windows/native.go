//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	namedpipe "github.com/wtalioy/JustConnect/corelib/internal/namedpipe/windows"
	"golang.org/x/sys/windows"
)

func creation(handle windows.Handle) uint64 {
	var born, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(handle, &born, &exited, &kernel, &user) != nil || exited.HighDateTime != 0 || exited.LowDateTime != 0 {
		return 0
	}
	return uint64(born.HighDateTime)<<32 | uint64(born.LowDateTime)
}
func Valid(p model.Process) bool {
	if p.PID <= 0 || p.Started == 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err == windows.ERROR_ACCESS_DENIED {
		times, queryErr := processTimes(context.Background())
		return queryErr == nil && times[uint32(p.PID)] == p.Started
	}
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	return creation(handle) == p.Started
}

func Read(ctx context.Context) ([]model.Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var result []model.Process
	var publicTimes map[uint32]uint64
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !model.Recognized(windows.UTF16ToString(entry.ExeFile[:])) {
			continue
		}
		p := model.Process{PID: int(entry.ProcessID)}
		handle, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if openErr != nil {
			if openErr == windows.ERROR_ACCESS_DENIED {
				if publicTimes == nil {
					times, queryErr := processTimes(ctx)
					if queryErr != nil {
						return nil, queryErr
					}
					publicTimes = times
				}
				p.Started = publicTimes[entry.ProcessID]
			}
			if openErr != windows.ERROR_INVALID_PARAMETER {
				result = append(result, p)
			}
			continue
		}
		p.Started = creation(handle)
		var size uint32
		windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation, nil, 0, &size)
		if size >= uint32(unsafe.Sizeof(windows.NTUnicodeString{})) && size <= 1<<20 {
			buffer := make([]byte, size)
			if windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation, unsafe.Pointer(&buffer[0]), size, &size) == nil {
				text := (*windows.NTUnicodeString)(unsafe.Pointer(&buffer[0]))
				base := uintptr(unsafe.Pointer(&buffer[0]))
				at := uintptr(unsafe.Pointer(text.Buffer))
				if text.Length%2 == 0 && at >= base && at-base <= uintptr(len(buffer)) && uintptr(text.Length) <= uintptr(len(buffer))-(at-base) {
					p.Args, _ = windows.DecomposeCommandLine(windows.UTF16ToString(unsafe.Slice(text.Buffer, int(text.Length)/2)))
				}
			}
		}
		var token windows.Token
		if windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token) == nil {
			owner, e := token.GetTokenUser()
			current, e2 := windows.GetCurrentProcessToken().GetTokenUser()
			if e == nil && e2 == nil && owner.User.Sid.Equals(current.User.Sid) {
				p.Home, _ = os.UserHomeDir()
			}
			token.Close()
		}
		windows.CloseHandle(handle)
		if Valid(p) {
			result = append(result, p)
		}
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return observeControllerPipes(ctx, result)
}

var waitNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

var tcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func OwnsTCP(ctx context.Context, p model.Process, target netip.AddrPort) bool {
	if ctx.Err() != nil || !Valid(p) {
		return false
	}
	// TCP_TABLE_OWNER_PID_LISTENER and MIB_TCP{,6}ROW_OWNER_PID from iprtrmib.h.
	for _, family := range []uintptr{windows.AF_INET, windows.AF_INET6} {
		var size uint32
		status, _, _ := tcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 3, 0)
		if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 4<<20 {
			continue
		}
		buffer := make([]byte, size)
		status, _, _ = tcpTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, family, 3, 0)
		if status != 0 || size > uint32(len(buffer)) || size < 4 {
			continue
		}
		width := 24
		if family == windows.AF_INET6 {
			width = 56
		}
		count := binary.LittleEndian.Uint32(buffer[:4])
		if uint64(count)*uint64(width) > uint64(size-4) {
			continue
		}
		for at := 4; at < 4+int(count)*width; at += width {
			row := buffer[at : at+width]
			var address netip.Addr
			var port uint16
			var pid uint32
			if family == windows.AF_INET {
				address = netip.AddrFrom4([4]byte(row[4:8]))
				port = binary.BigEndian.Uint16(row[8:10])
				pid = binary.LittleEndian.Uint32(row[20:24])
			} else {
				address = netip.AddrFrom16([16]byte(row[:16]))
				port = binary.BigEndian.Uint16(row[20:22])
				pid = binary.LittleEndian.Uint32(row[52:56])
			}
			if pid == uint32(p.PID) && port == target.Port() && model.ListenerMatches(address, target.Addr()) {
				return Valid(p)
			}
		}
	}
	return false
}

func DialIPC(ctx context.Context, p model.Process, address string) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !strings.HasPrefix(strings.ToLower(address), `\\.\pipe\`) || !Valid(p) {
		return nil, os.ErrPermission
	}
	path, err := windows.UTF16PtrFromString(address)
	if err != nil {
		return nil, os.ErrPermission
	}
	var handle windows.Handle
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		handle, err = windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err != windows.ERROR_PIPE_BUSY {
			break
		}
		// WaitNamedPipe cannot be canceled; bound each wait to keep context cancellation responsive.
		wait := 50 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			wait = max(time.Millisecond, time.Until(deadline))
		}
		available, _, waitErr := waitNamedPipe.Call(uintptr(unsafe.Pointer(path)), uintptr(wait.Milliseconds()))
		if available == 0 && waitErr != windows.ERROR_SEM_TIMEOUT {
			return nil, waitErr
		}
	}
	if err != nil {
		return nil, err
	}
	var pid uint32
	if windows.GetNamedPipeServerProcessId(handle, &pid) != nil || int(pid) != p.PID || !Valid(p) {
		windows.CloseHandle(handle)
		return nil, os.ErrPermission
	}
	stream, err := namedpipe.OwnNative(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	if ctx.Err() != nil {
		stream.Close()
		return nil, ctx.Err()
	}
	// net.Pipe supplies HTTP deadlines; the existing native stream owns cancellation and handle cleanup.
	client, relay := net.Pipe()
	go func() { defer relay.Close(); defer stream.Close(); io.Copy(stream, relay) }()
	go func() { defer relay.Close(); defer stream.Close(); io.Copy(relay, stream) }()
	return client, nil
}
