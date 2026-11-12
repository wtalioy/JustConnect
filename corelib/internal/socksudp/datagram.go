// Package socksudp validates the shared SOCKS UDP wire boundary (RFC 1928 section 7).
package socksudp

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/things-go/go-socks5/statute"
)

var ErrDatagram = errors.New("invalid SOCKS UDP datagram")

type Datagram struct {
	Data   []byte
	host   []byte
	port   int
	domain bool
}

// Destination formats the address when a new flow needs to dial it.
func (p Datagram) Destination() string {
	port := strconv.Itoa(p.port)
	if p.domain {
		return net.JoinHostPort(string(p.host), port)
	}
	return net.JoinHostPort(net.IP(p.host).String(), port)
}

// MatchesReply accepts a resolved IP for a name-only target, but never another name or port.
func (p Datagram) MatchesReply(target statute.AddrSpec) bool {
	if p.port != target.Port {
		return false
	}
	if target.IP != nil && (p.domain || !net.IP(p.host).Equal(target.IP)) {
		return false
	}
	return !p.domain || string(p.host) == target.FQDN
}

// Parse borrows the packet, accepts empty payloads, and rejects unsupported fragmentation.
func Parse(data []byte) (Datagram, error) {
	var packet Datagram
	if len(data) < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return packet, ErrDatagram
	}
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
		packet.domain = true
	default:
		return packet, ErrDatagram
	}
	end := offset + size
	if len(data) < end+2 {
		return packet, ErrDatagram
	}
	packet.port = int(binary.BigEndian.Uint16(data[end : end+2]))
	if packet.port == 0 {
		return packet, ErrDatagram
	}
	packet.host = data[offset:end]
	packet.Data = data[end+2:]
	return packet, nil
}
