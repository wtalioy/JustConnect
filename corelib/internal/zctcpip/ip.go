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

var (
	ErrInvalidLength    = errors.New("invalid packet length")
	ErrInvalidIPVersion = errors.New("invalid ip version")
	ErrInvalidChecksum  = errors.New("invalid checksum")
)

type IPv4Packet []byte

func (p IPv4Packet) TotalLen() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p IPv4Packet) HeaderLen() uint16 {
	return uint16(p[0]&0xf) * 4
}

func (p IPv4Packet) DataLen() uint16 {
	return p.TotalLen() - p.HeaderLen()
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

func (p IPv4Packet) SetSourceIP(ip net.IP) {
	if newIP := ip.To4(); newIP != nil {
		copy(p[12:16], newIP)
	}
}

func (p IPv4Packet) DestinationIP() net.IP {
	return net.IPv4(p[16], p[17], p[18], p[19])
}

func (p IPv4Packet) SetDestinationIP(ip net.IP) {
	if newIP := ip.To4(); newIP != nil {
		copy(p[16:20], newIP)
	}
}

func (p IPv4Packet) SetChecksum(sum [2]byte) {
	p[10] = sum[0]
	p[11] = sum[1]
}

func (p IPv4Packet) ResetChecksum() {
	p.SetChecksum(zeroChecksum)
	p.SetChecksum(Checksum(0, p[:p.HeaderLen()]))
}

// PseudoSum for tcp checksum
func (p IPv4Packet) PseudoSum() uint32 {
	sum := Sum(p[12:20])
	sum += uint32(p.Protocol())
	sum += uint32(p.DataLen())
	return sum
}

func (p IPv4Packet) Valid() bool {
	return len(p) >= IPv4HeaderSize && p[0]>>4 == IPv4Version && p.HeaderLen() >= IPv4HeaderSize &&
		p.TotalLen() >= p.HeaderLen() && int(p.TotalLen()) <= len(p)
}

func (p IPv4Packet) Verify() error {
	if len(p) < IPv4HeaderSize {
		return ErrInvalidLength
	}

	checksum := []byte{p[10], p[11]}
	headerLength := uint16(p[0]&0xF) * 4
	packetLength := binary.BigEndian.Uint16(p[2:])

	if p[0]>>4 != 4 {
		return ErrInvalidIPVersion
	}

	if uint16(len(p)) < packetLength || packetLength < headerLength {
		return ErrInvalidLength
	}

	p[10] = 0
	p[11] = 0
	defer copy(p[10:12], checksum)

	answer := Checksum(0, p[:headerLength])

	if answer[0] != checksum[0] || answer[1] != checksum[1] {
		return ErrInvalidChecksum
	}

	return nil
}
