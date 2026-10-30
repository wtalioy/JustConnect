package atrust

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
)

var conntrackKeySink string

func TestPacketMetadataRejectsMalformedHeaders(t *testing.T) {
	packet := makeUDPPacket(12345, 53)
	wrongVersion := append([]byte(nil), packet...)
	wrongVersion[0] = 0x65
	shortHeader := append([]byte(nil), packet...)
	shortHeader[0] = 0x44
	longHeader := append([]byte(nil), packet...)
	longHeader[0] = 0x4f
	shortTCP := makeTCPPacket(zctcpip.TCPSyn)[:39]
	binary.BigEndian.PutUint16(shortTCP[2:4], uint16(len(shortTCP)))
	shortUDP := append([]byte(nil), packet[:27]...)
	binary.BigEndian.PutUint16(shortUDP[2:4], uint16(len(shortUDP)))
	invalidUDP := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(invalidUDP[24:26], 7)
	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{"empty", nil}, {"short IP", packet[:19]}, {"wrong version", wrongVersion},
		{"short IP header", shortHeader}, {"long IP header", longHeader},
		{"truncated IP", packet[:27]}, {"short TCP", shortTCP},
		{"short UDP", shortUDP}, {"invalid UDP length", invalidUDP},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildPacketMeta(test.packet); !errors.Is(err, zctcpip.ErrInvalidLength) {
				t.Fatalf("malformed metadata = %v", err)
			}
			var tunnel L3Tunnel
			if err := tunnel.processIPV4(test.packet); !errors.Is(err, zctcpip.ErrInvalidLength) {
				t.Fatalf("malformed packet reached authorization: %v", err)
			}
		})
	}
}

func TestConntrackKeySeparatesPacketTuples(t *testing.T) {
	for _, family := range []int{4, 6} {
		meta := packetMeta{atype: family, proto: 17,
			srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2), srcPort: 12345, dstPort: 53}
		other := net.ParseIP("192.0.2.3")
		if family == 6 {
			meta.srcIP, meta.dstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
			other = net.ParseIP("2001:db9::1")
		}
		key := connTrackKey(meta)
		variants := []packetMeta{meta, meta, meta, meta, meta, meta}
		variants[0].atype = 10 - family
		variants[1].proto = 6
		variants[2].srcIP = other
		variants[3].dstIP = other
		variants[4].srcPort++
		variants[5].dstPort++
		seen := map[string]bool{key: true}
		for _, variant := range variants {
			value := connTrackKey(variant)
			if seen[value] {
				t.Fatal("distinct packet tuples shared a conntrack key", family, variant)
			}
			seen[value] = true
		}
		if family == 4 {
			meta.srcIP, meta.dstIP = meta.srcIP.To4(), meta.dstIP.To4()
			if connTrackKey(meta) != key {
				t.Fatal("equivalent IPv4 representations changed the conntrack key")
			}
		}
	}
}

func BenchmarkConnTrackKey(b *testing.B) {
	meta := packetMeta{atype: 4, proto: 17,
		srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2), srcPort: 12345, dstPort: 53}
	b.ReportAllocs()
	for b.Loop() {
		conntrackKeySink = connTrackKey(meta)
	}
}

func TestIsAuthTimeoutErr(t *testing.T) {
	err := fmt.Errorf("%w for 4:<client-ip>:<client-port>-<dns-server>:53", errL3TunnelAuthTimeout)
	if !isAuthTimeoutErr(err) {
		t.Fatal("expected wrapped l3 tunnel auth timeout to be recognized")
	}

	if isAuthTimeoutErr(nil) {
		t.Fatal("nil error must not be treated as auth timeout")
	}

	if isAuthTimeoutErr(fmt.Errorf("l3-tunnel auth timeout for unrelated text")) {
		t.Fatal("plain text error must not be treated as auth timeout")
	}
}
