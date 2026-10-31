// Package socksudp validates the shared SOCKS UDP wire boundary (RFC 1928 section 7).
package socksudp

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/things-go/go-socks5/statute"
)

var ErrDatagram = errors.New("invalid SOCKS UDP datagram")

// Parse borrows the packet, accepts empty payloads, and rejects unsupported fragmentation.
func Parse(data []byte) (statute.Datagram, error) {
	var packet statute.Datagram
	if len(data) < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return packet, ErrDatagram
	}
	packet.DstAddr.AddrType = data[3]
	offset, size := 4, 0
	switch data[3] {
	case statute.ATYPIPv4:
		size = net.IPv4len
	case statute.ATYPIPv6:
		size = net.IPv6len
	case statute.ATYPDomain:
		if len(data) < 5 || data[4] == 0 {
			return packet, ErrDatagram
		}
		offset, size = 5, int(data[4])
	default:
		return packet, ErrDatagram
	}
	end := offset + size
	if len(data) < end+2 {
		return packet, ErrDatagram
	}
	if data[3] == statute.ATYPDomain {
		packet.DstAddr.FQDN = string(data[offset:end])
	} else {
		packet.DstAddr.IP = net.IP(data[offset:end])
	}
	packet.DstAddr.Port = int(binary.BigEndian.Uint16(data[end : end+2]))
	if packet.DstAddr.Port == 0 {
		return packet, ErrDatagram
	}
	packet.Data = data[end+2:]
	return packet, nil
}
