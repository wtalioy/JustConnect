package zctcpip

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type IPProtocol = byte

// IPProtocol type
const (
	ICMP IPProtocol = 0x01
	TCP  IPProtocol = 0x06
	UDP  IPProtocol = 0x11
)

const (
	IPv4HeaderSize = 20

	IPv4Version = 4
)

var ErrInvalidLength = errors.New("invalid packet length")

type IPv4Packet []byte

func (p IPv4Packet) TotalLen() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p IPv4Packet) HeaderLen() uint16 {
	return uint16(p[0]&0xf) * 4
}

func (p IPv4Packet) Payload() []byte {
	return p[p.HeaderLen():p.TotalLen()]
}

func (p IPv4Packet) Protocol() IPProtocol {
	return p[9]
}

func (p IPv4Packet) SourceAddr() netip.Addr {
	return netip.AddrFrom4([4]byte(p[12:16]))
}

func (p IPv4Packet) DestinationAddr() netip.Addr {
	return netip.AddrFrom4([4]byte(p[16:20]))
}

func (p IPv4Packet) Valid() bool {
	return len(p) >= IPv4HeaderSize && p[0]>>4 == IPv4Version && p.HeaderLen() >= IPv4HeaderSize &&
		p.TotalLen() >= p.HeaderLen() && int(p.TotalLen()) <= len(p)
}
