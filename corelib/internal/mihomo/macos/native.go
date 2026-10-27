//go:build darwin

package macos

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/unix"
)

func stamp(p *unix.KinfoProc) uint64 {
	return uint64(p.Proc.P_starttime.Sec)*1_000_000 + uint64(p.Proc.P_starttime.Usec)
}
func Valid(p model.Process) bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", p.PID)
	return err == nil && info.Proc.P_pid == int32(p.PID) && p.Started != 0 && stamp(info) == p.Started
}

func Read(ctx context.Context) ([]model.Process, error) {
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var result []model.Process
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !model.Recognized(unix.ByteSliceToString(entry.Proc.P_comm[:])) {
			continue
		}
		p := model.Process{PID: int(entry.Proc.P_pid), Started: stamp(&entry)}
		data, err := unix.SysctlRaw("kern.procargs2", p.PID)
		if err == nil && len(data) >= 4 && len(data) <= 1<<20 {
			count := int(binary.NativeEndian.Uint32(data[:4]))
			data = data[4:]
			if end := bytes.IndexByte(data, 0); end >= 0 {
				data = bytes.TrimLeft(data[end+1:], "\x00")
			} else {
				data = nil
			}
			for i := 0; i < count && len(data) != 0; i++ {
				end := bytes.IndexByte(data, 0)
				if end < 0 {
					break
				}
				p.Args = append(p.Args, string(data[:end]))
				data = data[end+1:]
			}
		}
		if entry.Eproc.Ucred.Uid == uint32(os.Getuid()) {
			p.Home, _ = os.UserHomeDir()
		}
		// macOS exposes the process's actual cwd through its system lsof tool.
		output, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-a", "-p", strconv.Itoa(p.PID), "-d", "cwd", "-Fn").Output()
		if err == nil && len(output) <= 1<<20 {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "n") {
					p.Directory = line[1:]
				}
			}
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
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-a", "-p", strconv.Itoa(p.PID), "-iTCP", "-sTCP:LISTEN", "-Fftn").Output()
	if err != nil || len(output) > 1<<20 {
		return false
	}
	family := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "f") {
			family = ""
		}
		if strings.HasPrefix(line, "t") {
			family = line[1:]
		}
		if !strings.HasPrefix(line, "n") {
			continue
		}
		host, port, err := net.SplitHostPort(line[1:])
		if err != nil || port != strconv.Itoa(int(target.Port())) {
			continue
		}
		if host == "*" && ((family == "IPv4") == target.Addr().Unmap().Is4()) {
			return Valid(p)
		}
		address, err := netip.ParseAddr(host)
		if err == nil && model.ListenerMatches(address, target.Addr()) {
			return Valid(p)
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
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		valid = e == nil && pid == p.PID && Valid(p)
	})
	if err != nil || !valid {
		connection.Close()
		return nil, os.ErrPermission
	}
	return connection, nil
}
