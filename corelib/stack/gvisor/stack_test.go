package gvisor

import (
	"bytes"
	"context"
	"errors"
	clientpkg "github.com/wtalioy/JustConnect/corelib/client"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func outgoingPacket() *stack.PacketBuffer {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 40,
		Payload:            buffer.MakeWithData(bytes.Repeat([]byte{0xa5}, 1160)),
	})
	copy(packet.TransportHeader().Push(20), bytes.Repeat([]byte{0x06}, 20))
	copy(packet.NetworkHeader().Push(20), bytes.Repeat([]byte{0x45}, 20))
	return packet
}

func TestEndpointWritePacketsPreservesHeadersAndPayload(t *testing.T) {
	packet := outgoingPacket()
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	want := append(bytes.Repeat([]byte{0x45}, 20), bytes.Repeat([]byte{0x06}, 20)...)
	want = append(want, bytes.Repeat([]byte{0xa5}, 1160)...)
	var got []byte
	endpoint := Endpoint{l3Conn: &lifecycleConn{write: func(data []byte) (int, error) {
		got = bytes.Clone(data)
		return len(data), nil
	}}}
	if count, err := endpoint.WritePackets(list); err != nil || count != 1 || !bytes.Equal(got, want) {
		t.Fatal("packet headers or payload changed during endpoint write", count, err)
	}
}

func TestEndpointWritePacketsPreservesErrorHandling(t *testing.T) {
	for _, denied := range []bool{false, true} {
		packet := outgoingPacket()
		var list stack.PacketBufferList
		list.PushBack(packet)
		failure := errors.New("tunnel write failed")
		if denied {
			failure = clientpkg.ErrResourceNotFound
		}
		var reported error
		endpoint := Endpoint{l3Conn: &lifecycleConn{write: func([]byte) (int, error) { return 0, failure }},
			fail: func(err error) { reported = err }}
		count, err := endpoint.WritePackets(list)
		packet.DecRef()
		if denied {
			if count != 1 || err != nil || reported != nil {
				t.Fatal("resource denial broke the tunnel", count, err, reported)
			}
		} else if count != 0 || err == nil || reported != failure {
			t.Fatal("tunnel write failure was swallowed", count, err, reported)
		}
	}
}

func BenchmarkEndpointWritePackets(b *testing.B) {
	packet := outgoingPacket()
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	endpoint := Endpoint{l3Conn: &lifecycleConn{}}
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for b.Loop() {
		if count, err := endpoint.WritePackets(list); err != nil || count != 1 {
			b.Fatal(count, err)
		}
	}
}

func TestInboundPacketBufferExcludesUnreadCapacity(t *testing.T) {
	buf := []byte{0x45, 0x00, 0x12, 0x34, 0xde, 0xad}
	const bytesRead = 4
	packet := makeInboundPacketBuffer(buf, bytesRead)
	defer packet.DecRef()

	view := packet.ToView()
	defer view.Release()
	got := view.AsSlice()
	if !bytes.Equal(got, buf[:bytesRead]) {
		t.Fatalf("packet = % X, want only read bytes % X", got, buf[:bytesRead])
	}
}

type lifecycleClient struct {
	clientpkg.Client
	conn  *lifecycleConn
	ipErr error
}

func (c lifecycleClient) IP() (net.IP, error)                    { return net.IPv4(10, 0, 0, 2), c.ipErr }
func (c lifecycleClient) NewL3Conn() (io.ReadWriteCloser, error) { return c.conn, nil }
func (c lifecycleClient) CanUseTCPTunnel() bool                  { return false }

type lifecycleConn struct {
	closed     chan struct{}
	once       sync.Once
	panicRead  bool
	panicWrite bool
	write      func([]byte) (int, error)
}

func (c *lifecycleConn) Read([]byte) (int, error) {
	if c.panicRead {
		panic("private reader detail")
	}
	<-c.closed
	return 0, io.EOF
}
func (c *lifecycleConn) Write(data []byte) (int, error) {
	if c.panicWrite {
		panic("private writer detail")
	}
	if c.write != nil {
		return c.write(data)
	}
	return len(data), nil
}
func (c *lifecycleConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func TestStackRollbackAndCancelableDial(t *testing.T) {
	conn := &lifecycleConn{closed: make(chan struct{})}
	if s, err := NewStack(lifecycleClient{conn: conn, ipErr: errors.New("IP failed")}); err == nil {
		s.Close()
		t.Fatal("invalid IP accepted")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("partially initialized L3 connection not closed")
	}
	conn = &lifecycleConn{closed: make(chan struct{})}
	s, err := NewStack(lifecycleClient{conn: conn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if c, err := s.DialTCP(ctx, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}); err == nil {
		_ = c.Close()
		t.Fatal("unanswered TCP dial succeeded")
	}
	if time.Since(started) > time.Second {
		t.Fatal("gVisor TCP dial ignored cancellation")
	}
	s.Close()
	s.Close()
	select {
	case <-s.readDone:
	default:
		t.Fatal("stack reader survived Close")
	}
}

func TestStackReaderAndWriterPanicReturnFixedErrors(t *testing.T) {
	conn := &lifecycleConn{closed: make(chan struct{}), panicRead: true}
	s, err := NewStack(lifecycleClient{conn: conn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case err := <-s.Errors():
		if err.Error() != "network stack reader panicked" {
			t.Fatalf("reader error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader panic not returned")
	}
	errors := make(chan error, 1)
	endpoint := Endpoint{l3Conn: &lifecycleConn{panicWrite: true}, fail: func(err error) { errors <- err }}
	packet := makeInboundPacketBuffer([]byte{0x45}, 1)
	defer packet.DecRef()
	var list stack.PacketBufferList
	list.PushBack(packet)
	if _, err := endpoint.WritePackets(list); err == nil {
		t.Fatal("writer panic accepted")
	}
	if err := <-errors; err.Error() != "network stack writer panicked" {
		t.Fatalf("writer error = %v", err)
	}
}
