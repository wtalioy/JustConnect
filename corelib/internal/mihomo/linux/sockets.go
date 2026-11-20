//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/unix"
)

const (
	tcpStateListen = "0A"
	tcpIPv4Table   = "/proc/net/tcp"
	tcpIPv6Table   = "/proc/net/tcp6"
)

// tcpRow is one listening socket fact from a /proc/net/tcp{,6} table.
type tcpRow struct {
	inode int
	local netip.AddrPort
}

// OwnsTCP verifies that the process itself owns the loopback TCP listener.
func OwnsTCP(ctx context.Context, p model.Process, target netip.AddrPort) bool {
	targets := [...]netip.AddrPort{target}
	return len(FilterTCPListeners(ctx, p, targets[:])) != 0
}

// FilterTCPListeners keeps verified endpoints in their original order, in place.
// Both kernel TCP tables are read once and the rows are reused across every
// candidate: reading /proc/net/tcp{,6} is a kernel table walk, and a per-target
// read would repeat it for each advertised listener.
func FilterTCPListeners(ctx context.Context, p model.Process, targets []netip.AddrPort) []netip.AddrPort {
	if len(targets) == 0 || ctx.Err() != nil || !Valid(p) {
		return nil
	}
	inodes, err := processSocketInodes(p.PID)
	if err != nil || len(inodes) == 0 {
		return nil
	}
	rows, err := tcpListeners()
	if err != nil {
		return nil
	}
	owned := targets[:0]
	for _, target := range targets {
		if ctx.Err() != nil {
			return nil
		}
		if !target.Addr().IsLoopback() || target.Port() == 0 {
			continue
		}
		if listenerOwned(rows, inodes, target) {
			owned = append(owned, target)
		}
	}
	if len(owned) == 0 || ctx.Err() != nil || !Valid(p) {
		return nil
	}
	return owned
}

func listenerOwned(rows []tcpRow, inodes map[int]bool, target netip.AddrPort) bool {
	for _, row := range rows {
		if row.inode <= 0 || !inodes[row.inode] {
			continue
		}
		if row.local.Port() != target.Port() {
			continue
		}
		if model.ListenerMatches(row.local.Addr(), target.Addr()) {
			return true
		}
	}
	return false
}

// tcpListeners reads both TCP tables once. Addresses are hex-encoded big endian
// IPv4 or IPv4-in-IPv6 words followed by a colon and a hex port.
func tcpListeners() ([]tcpRow, error) {
	var result []tcpRow
	for _, table := range []string{tcpIPv4Table, tcpIPv6Table} {
		file, err := os.Open(table)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != tcpStateListen {
				continue
			}
			address, port, err := parseHexSocketAddress(fields[1])
			if err != nil {
				continue
			}
			inode, err := strconv.Atoi(fields[9])
			if err != nil {
				continue
			}
			result = append(result, tcpRow{inode: inode, local: netip.AddrPortFrom(address, port)})
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}
		file.Close()
	}
	return result, nil
}

func parseHexSocketAddress(field string) (netip.Addr, uint16, error) {
	address, port, found := strings.Cut(field, ":")
	if !found || len(address) != 8 && len(address) != 32 {
		return netip.Addr{}, 0, strconv.ErrSyntax
	}
	raw, err := hex.DecodeString(address)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	// The kernel prints each 32-bit address word in memory order, so every
	// four-byte group arrives little-endian and needs its bytes reversed.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	parsed, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, strconv.ErrSyntax
	}
	value, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return parsed.Unmap(), uint16(value), nil
}

// DialIPC opens the controller's Unix socket and verifies the connected peer.
// SO_PEERCRED is the Linux counterpart of macOS's LOCAL_PEERPID check.
func DialIPC(ctx context.Context, p model.Process, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", address)
	if err != nil {
		return nil, err
	}
	raw, err := connection.(*net.UnixConn).SyscallConn()
	if err != nil {
		connection.Close()
		return nil, err
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		credentials, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = e == nil && credentials != nil && int(credentials.Pid) == p.PID && Valid(p)
	})
	if err != nil || !valid {
		connection.Close()
		return nil, os.ErrPermission
	}
	return connection, nil
}
