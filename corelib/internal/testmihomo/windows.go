//go:build windows

package testmihomo

import (
	"crypto/rand"
	"io"
	"net"
	"sync"

	native "github.com/wtalioy/JustConnect/corelib/internal/namedpipe/windows"
	"golang.org/x/sys/windows"
)

func ipcName(string) string { return `\\.\pipe\verge-mihomo-test-` + rand.Text() }

type pipeListener struct {
	mu      sync.Mutex
	name    string
	pending windows.Handle
	closed  bool
	active  bool
}
type pipeAddress string

func (p pipeAddress) Network() string  { return "pipe" }
func (p pipeAddress) String() string   { return string(p) }
func (l *pipeListener) Addr() net.Addr { return pipeAddress(l.name) }
func createPipe(name string) (windows.Handle, error) {
	text, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(text, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 16, 65536, 65536, 0, nil)
}
func listenIPC(name string) (net.Listener, error) {
	handle, err := createPipe(name)
	if err != nil {
		return nil, err
	}
	return &pipeListener{name: name, pending: handle}, nil
}
func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.accept()
		// Discovery opens and immediately closes a pipe to read its owner PID.
		if err == windows.ERROR_NO_DATA || err == windows.ERROR_PIPE_NOT_CONNECTED || err == windows.ERROR_BROKEN_PIPE {
			continue
		}
		return connection, err
	}
}
func (l *pipeListener) accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	handle := l.pending
	if handle == 0 {
		var err error
		handle, err = createPipe(l.name)
		if err != nil {
			l.mu.Unlock()
			return nil, err
		}
		l.pending = handle
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.active = true
	operation := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(handle, &operation)
	l.mu.Unlock()
	if err == windows.ERROR_IO_PENDING {
		var count uint32
		err = windows.GetOverlappedResult(handle, &operation, &count, true)
	}
	windows.CloseHandle(event)
	l.mu.Lock()
	l.pending = 0
	l.active = false
	closed := l.closed
	l.mu.Unlock()
	if closed || err != nil && err != windows.ERROR_PIPE_CONNECTED {
		windows.CloseHandle(handle)
		if closed {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	stream, err := native.OwnNative(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	connection, relay := net.Pipe()
	go func() { defer relay.Close(); defer stream.Close(); io.Copy(stream, relay) }()
	go func() { defer relay.Close(); defer stream.Close(); io.Copy(relay, stream) }()
	return connection, nil
}
func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.pending != 0 {
		if l.active {
			windows.CancelIoEx(l.pending, nil)
		} else {
			windows.CloseHandle(l.pending)
			l.pending = 0
		}
	}
	return nil
}
