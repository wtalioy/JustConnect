package zctcpip

import (
	"encoding/binary"
)

const UDPHeaderSize = 8

type UDPPacket []byte

func (p UDPPacket) Length() uint16 {
	return binary.BigEndian.Uint16(p[4:])
}

func (p UDPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p UDPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p UDPPacket) Payload() []byte {
	return p[UDPHeaderSize:p.Length()]
}

func (p UDPPacket) Valid() bool {
	return len(p) >= UDPHeaderSize && p.Length() >= UDPHeaderSize && int(p.Length()) <= len(p)
}
