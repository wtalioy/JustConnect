package service

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type failingRelayRead struct{ net.Conn }

func (failingRelayRead) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRelayStreamReadErrorClosesBothEndpoints(t *testing.T) {
	for _, direction := range []string{"upstream", "downstream"} {
		t.Run(direction, func(t *testing.T) {
			client, relayClient := net.Pipe()
			target, relayTarget := net.Pipe()
			defer client.Close()
			defer target.Close()
			defer relayClient.Close()
			defer relayTarget.Close()
			var reader io.Reader = relayClient
			if direction == "upstream" {
				reader = failingRelayRead{relayClient}
			} else {
				relayTarget = failingRelayRead{relayTarget}
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				relayStream(relayClient, reader, relayTarget, func(err error) { t.Error(err) })
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("failed copy left the other direction blocked")
			}
			for _, conn := range []net.Conn{client, target} {
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("peer did not observe closure: %v", err)
				}
			}
		})
	}
}

func BenchmarkShortStreamRelay(b *testing.B) {
	client, clientPeer := net.Pipe()
	target, targetPeer := net.Pipe()
	defer client.Close()
	defer target.Close()
	clientPeer.Close()
	targetPeer.Close()
	b.ReportAllocs()
	for b.Loop() {
		relayStream(client, client, target, nil)
	}
}
