//go:build windows

package packetpipe

import (
	"fmt"
	nativepipe "github.com/wtalioy/JustConnect/corelib/internal/packetpipe/windows"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type pipePair struct{ server, client windows.Handle }

func nativePair(t *testing.T, synchronous bool) *pipePair {
	t.Helper()
	name := windows.StringToUTF16Ptr(fmt.Sprintf(`\\.\pipe\JustConnect-packet-test-%d-%d`, windows.GetCurrentProcessId(), time.Now().UnixNano()))
	server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	pair := &pipePair{server: server}
	t.Cleanup(func() {
		if pair.server != 0 {
			_ = windows.CloseHandle(pair.server)
		}
		if pair.client != 0 {
			_ = windows.CloseHandle(pair.client)
		}
	})
	var flags uint32 = windows.FILE_FLAG_OVERLAPPED
	if synchronous {
		flags = 0
	}
	client, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, flags|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	pair.client = client
	if err = windows.ConnectNamedPipe(server, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
		t.Fatal(err)
	}
	return pair
}

func TestNativeBorrowedPipe(t *testing.T) {
	pair := nativePair(t, false)
	server, client := pair.server, pair.client
	if _, err := Duplicate(uint64(client), windows.GetCurrentProcessId()+1, 1400, testLocal, testPeer); err == nil {
		t.Fatal("accepted wrong server process")
	}
	if _, err := Duplicate(uint64(server), windows.GetCurrentProcessId(), 1400, testLocal, testPeer); err == nil {
		t.Fatal("accepted server end as client")
	}
	left, err := Duplicate(uint64(client), windows.GetCurrentProcessId(), 1400, testLocal, testPeer)
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.CloseHandle(client); err != nil {
		t.Fatal(err)
	}
	pair.client = 0
	stream, err := nativepipe.OwnNative(server)
	if err != nil {
		t.Fatal(err)
	}
	pair.server = 0
	right, _ := New(stream, 1400, testLocal, testPeer)
	exercisePair(t, left, right)
}

func TestNativeRejectsSynchronousPipe(t *testing.T) {
	pair := nativePair(t, true)
	client := pair.client
	if _, err := Duplicate(uint64(client), windows.GetCurrentProcessId(), 1400, testLocal, testPeer); err == nil {
		t.Fatal("accepted a non-cancellable pipe")
	}
}

func TestNativeRejectsReadOnlyPipe(t *testing.T) {
	pair := nativePair(t, false)
	var readOnly windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), pair.client, windows.CurrentProcess(), &readOnly, windows.GENERIC_READ, false, 0); err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(readOnly)
	if _, err := Duplicate(uint64(readOnly), windows.GetCurrentProcessId(), 1400, testLocal, testPeer); err == nil {
		t.Fatal("accepted a pipe without write permission")
	}
}

func TestNativeCloseInterruptsPendingIO(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprint("write=", write), func(t *testing.T) {
			pair := nativePair(t, false)
			client := pair.client
			device, err := Duplicate(uint64(client), windows.GetCurrentProcessId(), 1400, testLocal, testPeer)
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			done := make(chan error, 1)
			go func() {
				if write {
					for {
						if _, err := device.Write(testPacket(1400)); err != nil {
							done <- err
							return
						}
					}
				} else {
					_, err := device.Read(make([]byte, 1400))
					done <- err
				}
			}()
			time.Sleep(20 * time.Millisecond)
			closed := make(chan error, 1)
			go func() { closed <- device.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("close did not cancel pending native I/O")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("pending I/O survived close")
				}
			case <-time.After(time.Second):
				t.Fatal("native worker survived close")
			}
		})
	}
}
