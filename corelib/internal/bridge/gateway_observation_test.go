package bridge

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
)

type observedUDPReply struct {
	net.Conn
	gateway *gateway
	count   chan int32
}

func (c *observedUDPReply) Write(packet []byte) (int, error) {
	n, err := c.Conn.Write(packet)
	// Witness the count after bytes are visible but before the writer returns.
	c.count <- c.gateway.udpCount.Load()
	return n, err
}

func TestGatewayCountsUDPBeforeReplyCanBeObserved(t *testing.T) {
	client, server := net.Pipe()
	g := &gateway{}
	observed, done := make(chan int32, 1), make(chan struct{})
	go func() { defer close(done); g.serveL3(&observedUDPReply{server, g, observed}) }()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("observed UDP")
	packet := make([]byte, 20+8+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, byte(zctcpip.UDP)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 10})
	ip, udp := zctcpip.IPv4Packet(packet), zctcpip.UDPPacket(packet[20:])
	udp.SetSourcePort(12345)
	udp.SetDestinationPort(53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	udp.ResetChecksum(ip.PseudoSum())
	ip.ResetChecksum()
	frame := append([]byte{5, 0x14, 0, 0, 0, 1, byte(len(packet) >> 8), byte(len(packet))}, packet...)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4+len(packet))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply[:4], []byte{5, 0x94, byte(len(packet) >> 8), byte(len(packet))}) || !bytes.Equal(reply[32:], payload) {
		t.Fatal("actual L3 UDP reply changed")
	}
	if count := <-observed; count != 1 {
		t.Fatalf("visible UDP reply preceded its gateway count: %d", count)
	}
}
