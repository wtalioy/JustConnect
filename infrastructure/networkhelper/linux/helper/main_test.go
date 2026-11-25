//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// serveRoundTrip drives the real serve loop over a socketpair, with a test
// client standing in for the application.
type testClient struct {
	file     *os.File
	serveErr chan error
}

func newTestClient(t *testing.T) (*testClient, *helperSession) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(fds[1], true); err != nil {
		t.Fatal(err)
	}
	app := os.NewFile(uintptr(fds[0]), "test-app")
	server := os.NewFile(uintptr(fds[1]), "test-server")
	session := &helperSession{uid: os.Getuid(), pid: os.Getpid()}
	serveErr := make(chan error, 1)
	go func() {
		defer close(serveErr)
		defer server.Close()
		serveErr <- serve(server, fds[1], session)
	}()
	t.Cleanup(func() {
		app.Close()
		server.Close()
		<-serveErr
	})
	return &testClient{file: app, serveErr: serveErr}, session
}

func (c *testClient) send(t *testing.T, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	if _, err := c.file.Write(frame); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func (c *testClient) receive(t *testing.T) *response {
	t.Helper()
	if err := c.file.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	header := make([]byte, 4)
	if err := readFull(c.file, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	length := int(binary.BigEndian.Uint32(header))
	payload := make([]byte, length)
	if err := readFull(c.file, payload); err != nil {
		t.Fatalf("read body: %v", err)
	}
	reply := &response{}
	if err := json.Unmarshal(payload, reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	return reply
}

// expectClosed waits for the helper side to drop the connection and asserts
// a clean shutdown; use expectCorrupted when protocol corruption is expected.
func (c *testClient) expectClosed(t *testing.T) {
	c.expectCloseWith(t, true)
}

func (c *testClient) expectCorrupted(t *testing.T) {
	c.expectCloseWith(t, false)
}

func (c *testClient) expectCloseWith(t *testing.T, clean bool) {
	t.Helper()
	if err := c.file.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buffer := make([]byte, 16)
	_, err := c.file.Read(buffer)
	if err == nil {
		t.Fatal("helper kept the connection open")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("unexpected close error %v", err)
	}
	select {
	case serveErr := <-c.serveErr:
		if clean && serveErr != nil {
			t.Fatalf("serve failed: %v", serveErr)
		}
		if !clean && serveErr == nil {
			t.Fatal("protocol corruption was not reported")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not finish")
	}
}

func TestServeProbeAndClose(t *testing.T) {
	withStateRoot(t)
	_ = os.MkdirAll(stateRoot, 0700)
	client, _ := newTestClient(t)

	client.send(t, envelope(opProbe))
	reply := client.receive(t)
	if reply.Status != statusOK || reply.Operation != opProbe {
		t.Fatalf("probe failed: %+v", reply)
	}

	client.send(t, envelope(opClose))
	reply = client.receive(t)
	if reply.Status != statusOK || reply.Operation != opClose {
		t.Fatalf("close failed: %+v", reply)
	}
	client.expectClosed(t)
}

func TestServeRejectsUnknownOperation(t *testing.T) {
	withStateRoot(t)
	_ = os.MkdirAll(stateRoot, 0700)
	client, _ := newTestClient(t)

	client.send(t, map[string]any{
		"version": helperProtocol, "operation": "unite",
		"owner": testOwner, "request_id": testRequest,
	})
	reply := client.receive(t)
	if reply.Status != statusFailed {
		t.Fatalf("unknown operation accepted: %+v", reply)
	}

	client.send(t, envelope(opProbe))
	if reply := client.receive(t); reply.Status != statusOK {
		t.Fatalf("helper stopped serving after a bad request: %+v", reply)
	}
}

func TestServeRejectsOversizedFrame(t *testing.T) {
	withStateRoot(t)
	_ = os.MkdirAll(stateRoot, 0700)
	client, _ := newTestClient(t)

	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame[:4], maxRequestBytes+1)
	if _, err := client.file.Write(frame); err != nil {
		t.Fatal(err)
	}
	client.expectCorrupted(t)
}

func TestServeRejectsInvalidApply(t *testing.T) {
	withStateRoot(t)
	_ = os.MkdirAll(stateRoot, 0700)
	client, _ := newTestClient(t)

	apply := envelope(opApply)
	apply["address"], apply["peer"], apply["mtu"] = "127.0.0.1", "10.22.4.2", 1400
	apply["prefixes"] = []string{"10.50.0.0/16"}
	client.send(t, apply)
	reply := client.receive(t)
	if reply.Status != statusFailed {
		t.Fatalf("invalid address accepted: %+v", reply)
	}
	// The failure must not leave owned state behind.
	client.send(t, envelope(opClose))
	if reply := client.receive(t); reply.Status != statusOK {
		t.Fatalf("close after failure: %+v", reply)
	}
	client.expectClosed(t)
}
