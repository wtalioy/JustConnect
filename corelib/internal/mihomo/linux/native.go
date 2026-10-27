//go:build linux

package linux

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/unix"
)

func started(pid int) uint64 {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0
	}
	value, _ := strconv.ParseUint(fields[19], 10, 64)
	return value
}
func Valid(p model.Process) bool { return p.Started != 0 && started(p.PID) == p.Started }

func Read(ctx context.Context) ([]model.Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var result []model.Process
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		root := filepath.Join("/proc", entry.Name())
		name, err := os.ReadFile(root + "/comm")
		if err != nil || !model.Recognized(strings.TrimSpace(string(name))) {
			continue
		}
		p := model.Process{PID: pid, Started: started(pid)}
		args, err := os.ReadFile(root + "/cmdline")
		if err == nil && len(args) <= 1<<20 {
			p.Args = strings.Split(strings.TrimRight(string(args), "\x00"), "\x00")
		}
		p.Directory, _ = os.Readlink(root + "/cwd")
		var info unix.Stat_t
		if unix.Stat(root, &info) == nil && info.Uid == uint32(os.Getuid()) {
			p.Home, _ = os.UserHomeDir()
		}
		if Valid(p) {
			result = append(result, p)
		}
	}
	return result, nil
}

func OwnsTCP(ctx context.Context, p model.Process, target netip.AddrPort) bool {
	if ctx.Err() != nil || !Valid(p) {
		return false
	}
	var inode string
	for _, name := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile("/proc/net/" + name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.ParseUint(parts[1], 16, 16)
			if err != nil || uint16(port) != target.Port() {
				continue
			}
			bytes, err := hex.DecodeString(parts[0])
			if err != nil || (len(bytes) != 4 && len(bytes) != 16) {
				continue
			}
			// procfs writes each native uint32 in host byte order.
			for offset := 0; offset < len(bytes); offset += 4 {
				bytes[offset], bytes[offset+3] = bytes[offset+3], bytes[offset]
				bytes[offset+1], bytes[offset+2] = bytes[offset+2], bytes[offset+1]
			}
			address, ok := netip.AddrFromSlice(bytes)
			if !ok || !model.ListenerMatches(address, target.Addr()) {
				continue
			}
			inode = "socket:[" + fields[9] + "]"
			entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(p.PID), "fd"))
			if err != nil {
				return false
			}
			for _, entry := range entries {
				link, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(p.PID), "fd", entry.Name()))
				if link == inode {
					return Valid(p)
				}
			}
		}
	}
	return false
}

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
		peer, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = e == nil && int(peer.Pid) == p.PID && Valid(p)
	})
	if err != nil || !valid {
		connection.Close()
		return nil, os.ErrPermission
	}
	return connection, nil
}
