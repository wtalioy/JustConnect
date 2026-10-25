//go:build windows

package packetpipe

import (
	"io"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_INFORMATION_CLASS and FILE_MODE_INFORMATION flags from the Windows SDK.
const (
	fileAccessInformation     = 8
	fileModeInformation       = 16
	fileSynchronousIOAlert    = 0x10
	fileSynchronousIONonalert = 0x20
)

// NativeStream owns an overlapped byte-pipe handle without registering a second IOCP.
type NativeStream struct {
	handle   windows.Handle
	mu       sync.Mutex
	pending  sync.WaitGroup
	closed   bool
	once     sync.Once
	closeErr error
}

// OwnNative takes ownership only on success. No I/O may already be pending.
func OwnNative(handle windows.Handle) (*NativeStream, error) {
	if kind, err := windows.GetFileType(handle); err != nil || kind != windows.FILE_TYPE_PIPE {
		return nil, windows.ERROR_INVALID_HANDLE
	}
	var flags, mode uint32
	if err := windows.GetNamedPipeInfo(handle, &flags, nil, nil, nil); err != nil {
		return nil, err
	}
	if flags&windows.PIPE_TYPE_MESSAGE != 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	if err := windows.GetNamedPipeHandleState(handle, &mode, nil, nil, nil, nil, 0); err != nil {
		return nil, err
	}
	if mode&(windows.PIPE_READMODE_MESSAGE|windows.PIPE_NOWAIT) != 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	// Reject synchronous handles before starting any I/O, as Go's IsNonblock does.
	var ioMode uint32
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtQueryInformationFile(handle, &status, (*byte)(unsafe.Pointer(&ioMode)), uint32(unsafe.Sizeof(ioMode)), fileModeInformation); err != nil {
		return nil, err
	}
	if ioMode&(fileSynchronousIOAlert|fileSynchronousIONonalert) != 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	var access uint32
	if err := windows.NtQueryInformationFile(handle, &status, (*byte)(unsafe.Pointer(&access)), uint32(unsafe.Sizeof(access)), fileAccessInformation); err != nil {
		return nil, err
	}
	if access&(windows.FILE_READ_DATA|windows.FILE_WRITE_DATA) != windows.FILE_READ_DATA|windows.FILE_WRITE_DATA {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	return &NativeStream{handle: handle}, nil
}

func Duplicate(value uint64, serverPID uint32) (*NativeStream, error) {
	if value == 0 || uint64(uintptr(value)) != value || serverPID == 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	var handle windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(value), windows.CurrentProcess(), &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = windows.CloseHandle(handle)
		}
	}()
	var actual, flags uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &actual); err != nil || actual != serverPID {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	if err := windows.GetNamedPipeInfo(handle, &flags, nil, nil, nil); err != nil || flags&windows.PIPE_SERVER_END != 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	stream, err := OwnNative(handle)
	if err != nil {
		return nil, err
	}
	owned = true
	return stream, nil
}

func (s *NativeStream) transfer(data []byte, write bool) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	operation := windows.Overlapped{HEvent: event}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, windows.ERROR_OPERATION_ABORTED
	}
	s.pending.Add(1)
	var count uint32
	if write {
		err = windows.WriteFile(s.handle, data, &count, &operation)
	} else {
		err = windows.ReadFile(s.handle, data, &count, &operation)
	}
	s.mu.Unlock()
	defer s.pending.Done()
	if err == windows.ERROR_IO_PENDING {
		err = windows.GetOverlappedResult(s.handle, &operation, &count, true)
	}
	runtime.KeepAlive(data)
	if err == windows.ERROR_BROKEN_PIPE {
		err = io.EOF
	}
	return int(count), err
}

func (s *NativeStream) Read(data []byte) (int, error)  { return s.transfer(data, false) }
func (s *NativeStream) Write(data []byte) (int, error) { return s.transfer(data, true) }

func (s *NativeStream) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		err := windows.CancelIoEx(s.handle, nil)
		s.mu.Unlock()
		s.pending.Wait()
		s.closeErr = windows.CloseHandle(s.handle)
		if err != nil && err != windows.ERROR_NOT_FOUND {
			s.closeErr = err
		}
	})
	return s.closeErr
}
