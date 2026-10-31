//go:build windows

package testmihomo

import (
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestIPCListenerRetainsItsNameBetweenAccepts(t *testing.T) {
	listener, err := listenIPC(ipcName(""))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	path, _ := windows.UTF16PtrFromString(listener.Addr().String())
	for range 2 {
		// A listening pipe must remain connectable even before the next Accept starts.
		client, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err != nil {
			t.Fatal("listener lost its public name between clients", err)
		}
		accepted := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if connection != nil {
				connection.Close()
			}
			accepted <- err
		}()
		select {
		case err := <-accepted:
			windows.CloseHandle(client)
			if err != nil {
				t.Fatal("pending owned client was not accepted", err)
			}
		case <-time.After(5 * time.Second):
			windows.CloseHandle(client)
			t.Fatal("pending owned client was not accepted")
		}
	}
}

func TestIPCListenerSurvivesAnAlreadyDisconnectedProbe(t *testing.T) {
	listener, err := listenIPC(ipcName(""))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pipe := listener.(*pipeListener)
	path, _ := windows.UTF16PtrFromString(pipe.name)
	probe, err := windows.CreateFile(path, 0, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(probe)
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if connection != nil {
			connection.Close()
		}
		accepted <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	wait := windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")
	for {
		select {
		case err := <-accepted:
			t.Fatal("closed discovery probe stopped the listener", err)
		default:
		}
		available, _, _ := wait.Call(uintptr(unsafe.Pointer(path)), 10)
		if available != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not replace the disconnected pipe instance")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(client)
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal("next real client could not connect", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("next real client was not accepted")
	}
	listener.Close()
	if _, err := listener.Accept(); err != net.ErrClosed {
		t.Fatal("closed listener accepted another client", err)
	}
}
