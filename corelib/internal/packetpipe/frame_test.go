package packetpipe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

var testLocal = netip.MustParseAddr("192.0.2.1")
var testPeer = netip.MustParseAddr("192.0.2.2")

func testPacket(size int) []byte {
	p := make([]byte, size)
	p[0], p[9] = 0x45, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	copy(p[12:16], testLocal.AsSlice())
	copy(p[16:20], testPeer.AsSlice())
	for i := 28; i < size; i++ {
		p[i] = byte(i)
	}
	return p
}

func exercisePair(t *testing.T, left, right *Device) {
	t.Helper()
	defer left.Close()
	defer right.Close()
	for _, size := range []int{28, 29, 1400} {
		packet := testPacket(size)
		done := make(chan error, 1)
		go func() {
			_, err := left.Write(packet)
			if err == nil {
				buffer := make([]byte, 1400)
				var n int
				n, err = left.Read(buffer)
				if err == nil && !bytes.Equal(buffer[:n], packet) {
					err = errors.New("response bytes changed")
				}
			}
			done <- err
		}()
		buffer := make([]byte, 1400)
		n, err := right.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("receive: size=%d n=%d err=%v", size, n, err)
		}
		if _, err = right.Write(buffer[:n]); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPacketBoundaries(t *testing.T) {
	a, b := net.Pipe()
	left, _ := New(a, 1400, testLocal, testPeer)
	right, _ := New(b, 1400, testLocal, testPeer)
	exercisePair(t, left, right)
}

func TestRejectFrameClosesTransport(t *testing.T) {
	for _, kind := range []string{"short", "oversized", "version", "header", "length", "truncated", "small-buffer"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			device, _ := New(a, 1400, testLocal, testPeer)
			packet := testPacket(28)
			var size uint32 = uint32(len(packet))
			switch kind {
			case "short":
				size = 19
			case "oversized":
				size = 65536
			case "version":
				packet[0] = 0x65
			case "header":
				packet[0] = 0x4f
			case "length":
				packet[3]--
			case "truncated":
				packet = packet[:21]
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				_ = binary.Write(b, binary.BigEndian, size)
				_, _ = b.Write(packet)
			}()
			capacity := 1400
			if kind == "small-buffer" {
				capacity = 20
			}
			if n, err := device.Read(make([]byte, capacity)); err == nil || n != 0 {
				t.Fatalf("accepted %s: %d %v", kind, n, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("invalid frame retained its sender")
			}
			if _, err := device.Write(testPacket(28)); err == nil {
				t.Fatal("damaged stream was reused")
			}
		})
	}
}

type partialStream struct {
	bytes.Buffer
	zero bool
}

func (s *partialStream) Write(data []byte) (int, error) {
	if s.zero {
		return 0, nil
	}
	if len(data) > 3 {
		data = data[:3]
	}
	return s.Buffer.Write(data)
}
func (*partialStream) Close() error { return nil }

func TestPartialWritesAndInvalidOutput(t *testing.T) {
	stream := new(partialStream)
	device, _ := New(stream, 1400, testLocal, testPeer)
	if _, err := device.Write(testPacket(28)); err != nil {
		t.Fatal(err)
	}
	if n, err := device.Read(make([]byte, 1400)); n != 28 || err != nil {
		t.Fatalf("short writes lost framing: %d %v", n, err)
	}
	for _, packet := range [][]byte{nil, make([]byte, 19), testPacket(1401)} {
		if _, err := device.Write(packet); !errors.Is(err, ErrFrame) {
			t.Fatalf("invalid output accepted: %v", err)
		}
	}
	stream.zero = true
	if _, err := device.Write(testPacket(28)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero progress: %v", err)
	}
}
