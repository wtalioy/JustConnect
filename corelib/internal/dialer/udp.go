package dialer

import "net"

func SendBufferSize(conn *net.UDPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var size int
	var queryErr error
	if err := raw.Control(func(fd uintptr) { size, queryErr = sendBufferSize(fd) }); err != nil {
		return 0, err
	}
	return size, queryErr
}
