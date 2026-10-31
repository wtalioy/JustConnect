package socksudp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/things-go/go-socks5/statute"
)

func TestDatagramBoundaryIncludesEmptyIPv6AndDomainPayloads(t *testing.T) {
	for _, address := range []string{"192.0.2.7:53", "[2001:db8::7]:53", "a:53", "owned.campus.test:53"} {
		for _, payload := range [][]byte{nil, []byte("owned packet")} {
			original, err := statute.NewDatagram(address, payload)
			if err != nil {
				t.Fatal(err)
			}
			wire := original.Bytes()
			packet, err := Parse(wire)
			if err != nil || packet.DstAddr.String() != address || !bytes.Equal(packet.Data, payload) {
				t.Fatal("valid datagram lost its address or empty payload", address, packet, err)
			}
			header := original.Header()
			for length := range len(header) {
				if _, err := Parse(header[:length]); !errors.Is(err, ErrDatagram) {
					t.Fatal("truncated datagram accepted", address, length)
				}
			}
			for _, offset := range []int{0, 1, 2, 3, len(header) - 2} {
				invalid := bytes.Clone(header)
				invalid[offset] = 255
				if offset == len(header)-2 {
					invalid[offset], invalid[offset+1] = 0, 0
				}
				if _, err := Parse(invalid); !errors.Is(err, ErrDatagram) {
					t.Fatal("invalid RSV/fragment/type/port accepted", address, offset)
				}
			}
		}
	}
}
