// Package packetpipe carries IPv4 packets over the Windows helper's byte pipe.
package packetpipe

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"

	deviceaddr "github.com/wtalioy/JustConnect/corelib/internal/tundevice/address"
)

var ErrFrame = errors.New("invalid helper IPv4 packet frame")

type Device struct {
	stream      io.ReadWriteCloser
	local, peer netip.Addr
	mtu         uint32
	read, write sync.Mutex
	close       sync.Once
	closeErr    error
}

func New(stream io.ReadWriteCloser, mtu uint32, local, peer netip.Addr) (*Device, error) {
	if stream == nil || mtu < 68 || mtu > 65535 || !deviceaddr.ValidIPv4Pair(local, peer) {
		return nil, ErrFrame
	}
	return &Device{stream: stream, mtu: mtu, local: local, peer: peer}, nil
}

func (d *Device) TUNAddresses() (netip.Addr, netip.Addr) { return d.local, d.peer }

func valid(packet []byte) bool {
	return len(packet) >= 20 && packet[0]>>4 == 4 && int(packet[0]&15)*4 >= 20 &&
		int(packet[0]&15)*4 <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
}

func (d *Device) Read(packet []byte) (int, error) {
	d.read.Lock()
	defer d.read.Unlock()
	var header [4]byte
	if _, err := io.ReadFull(d.stream, header[:]); err != nil {
		_ = d.Close()
		return 0, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 20 || size > d.mtu || uint64(size) > uint64(len(packet)) {
		_ = d.Close()
		return 0, ErrFrame
	}
	if _, err := io.ReadFull(d.stream, packet[:size]); err != nil {
		_ = d.Close()
		return 0, err
	}
	if !valid(packet[:size]) {
		_ = d.Close()
		return 0, ErrFrame
	}
	return int(size), nil
}

func (d *Device) Write(packet []byte) (int, error) {
	if uint64(len(packet)) > uint64(d.mtu) || !valid(packet) {
		return 0, ErrFrame
	}
	d.write.Lock()
	defer d.write.Unlock()
	frame := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint32(frame, uint32(len(packet)))
	copy(frame[4:], packet)
	for len(frame) != 0 {
		n, err := d.stream.Write(frame)
		if err == nil && n == 0 {
			err = io.ErrShortWrite
		}
		if err != nil {
			_ = d.Close()
			return 0, err
		}
		frame = frame[n:]
	}
	return len(packet), nil
}

func (d *Device) Close() error {
	d.close.Do(func() { d.closeErr = d.stream.Close() })
	return d.closeErr
}
