package zctcpip

import (
	"encoding/binary"
	"errors"
	"net"
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

func (p IPv4Packet) SourceIP() net.IP {
	return net.IPv4(p[12], p[13], p[14], p[15])
}

func (p IPv4Packet) DestinationIP() net.IP {
	return net.IPv4(p[16], p[17], p[18], p[19])
}

func (p IPv4Packet) Valid() bool {
	return len(p) >= IPv4HeaderSize && p[0]>>4 == IPv4Version && p.HeaderLen() >= IPv4HeaderSize &&
		p.TotalLen() >= p.HeaderLen() && int(p.TotalLen()) <= len(p)
}
