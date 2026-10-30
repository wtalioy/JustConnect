package zctcpip

import (
	"encoding/binary"
)

const (
	TCPFin uint16 = 1 << 0
	TCPSyn uint16 = 1 << 1
	TCPRst uint16 = 1 << 2
	TCPAck uint16 = 1 << 4
)

const TCPHeaderSize = 20

type TCPPacket []byte

func (p TCPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p TCPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p TCPPacket) Flags() uint16 {
	return uint16(p[13]) | uint16(p[12]&1)<<8
}

func (p TCPPacket) Valid() bool {
	return len(p) >= TCPHeaderSize
}
