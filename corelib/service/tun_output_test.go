package service

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func tunOutputPacket(split bool) (*stack.PacketBuffer, []byte) {
	const size = 1200
	payload := bytes.Repeat([]byte{0xa5}, size)
	if !split {
		return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)}), payload
	}
	payload[0], payload[20] = 0x45, 0x06
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 64,
		Payload:            buffer.MakeWithData(payload[40:]),
	})
	copy(packet.TransportHeader().Push(20), payload[20:40])
	copy(packet.NetworkHeader().Push(20), payload[:20])
	return packet, payload
}

func TestTUNWritePacket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		split   bool
		scratch int
	}{
		{"contiguous", false, 1500},
		{"split-header", true, 1500},
		{"split-larger-than-scratch", true, 576},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, want := tunOutputPacket(tc.split)
			defer packet.DecRef()
			var output bytes.Buffer
			if err := writeTUNPacket(&output, packet, make([]byte, tc.scratch)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("incorrect packet data, got %d bytes, want %d", output.Len(), len(want))
			}
		})
	}
	packet, _ := tunOutputPacket(false)
	defer packet.DecRef()
	if err := writeTUNPacket(tunShortWriter{}, packet, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

type tunShortWriter struct{}

func (tunShortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

type tunPacketSink struct{ last byte }

func (s *tunPacketSink) Write(data []byte) (int, error) {
	s.last = data[len(data)-1]
	return len(data), nil
}

func BenchmarkTUNWritePacket(b *testing.B) {
	for _, tc := range []struct {
		name  string
		split bool
	}{{"contiguous", false}, {"split-header", true}} {
		b.Run(tc.name, func(b *testing.B) {
			packet, want := tunOutputPacket(tc.split)
			defer packet.DecRef()
			sink := &tunPacketSink{}
			scratch := make([]byte, 1500)
			b.ReportAllocs()
			b.SetBytes(int64(len(want)))
			for b.Loop() {
				if err := writeTUNPacket(sink, packet, scratch); err != nil {
					b.Fatal(err)
				}
			}
			if sink.last != want[len(want)-1] {
				b.Fatal("payload did not reach writer")
			}
		})
	}
}
