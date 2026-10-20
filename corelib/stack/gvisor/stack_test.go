package gvisor

import (
	"bytes"
	"context"
	"errors"
	clientpkg "github.com/wtalioy/JustConnect/corelib/client"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

var joinedPacketSink []byte

func TestJoinPacketSlicesPreservesContent(t *testing.T) {
	slices := [][]byte{{0x45, 0x00}, {}, {0x12, 0x34, 0x56}, {0x78}}
	want := []byte{0x45, 0x00, 0x12, 0x34, 0x56, 0x78}
	if got := joinPacketSlices(slices); !bytes.Equal(got, want) {
		t.Fatalf("joinPacketSlices() = % X, want % X", got, want)
	}
}

func TestInboundPacketBufferExcludesUnreadCapacity(t *testing.T) {
	buf := []byte{0x45, 0x00, 0x12, 0x34, 0xde, 0xad}
	const bytesRead = 4
	packet := makeInboundPacketBuffer(buf, bytesRead)
	defer packet.DecRef()

	got := joinPacketSlices(packet.AsSlices())
	if !bytes.Equal(got, buf[:bytesRead]) {
		t.Fatalf("packet = % X, want only read bytes % X", got, buf[:bytesRead])
	}
}

func TestJoinPacketSlicesAllocatesOnce(t *testing.T) {
	slices := [][]byte{make([]byte, 20), make([]byte, 20), make([]byte, 1160)}
	if allocs := testing.AllocsPerRun(1000, func() { joinedPacketSink = joinPacketSlices(slices) }); allocs != 1 {
		t.Fatalf("joinPacketSlices allocations = %v, want 1", allocs)
	}
}

func BenchmarkJoinPacketSlices(b *testing.B) {
	slices := [][]byte{make([]byte, 20), make([]byte, 20), make([]byte, 1160)}
	b.ReportAllocs()
	b.SetBytes(1200)
	for i := 0; i < b.N; i++ {
		joinedPacketSink = joinPacketSlices(slices)
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
