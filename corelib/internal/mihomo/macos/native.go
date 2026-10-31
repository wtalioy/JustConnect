//go:build darwin

package macos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"golang.org/x/sys/unix"
)

const maxNativeReadBytes = 1 << 20

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
	targets := make(map[int]bool)
	for _, entry := range entries {
		if entry.Eproc.Ucred.Uid != uint32(os.Getuid()) && model.Recognized(unix.ByteSliceToString(entry.Proc.P_comm[:])) {
			targets[int(entry.Proc.P_pid)] = true
		}
	}
	var observed map[int][]string
	if len(targets) != 0 {
		observed, _ = observedIPC(ctx, targets)
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !model.Recognized(unix.ByteSliceToString(entry.Proc.P_comm[:])) {
			continue
		}
		p := model.Process{PID: int(entry.Proc.P_pid), Started: stamp(&entry)}
		data, err := unix.SysctlRaw("kern.procargs2", p.PID)
		if err == nil && len(data) >= 4 && len(data) <= maxNativeReadBytes {
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
		} else {
			// KERN_PROCARGS2 denies cross-UID reads; observed listeners expose neither config nor secrets.
			p.IPC = observed[p.PID]
		}

		if len(p.Args) != 0 {
			// Relative configuration paths require the process's actual cwd.
			output, err := commandOutput(ctx, "/usr/sbin/lsof", "-a", "-p", strconv.Itoa(p.PID), "-d", "cwd", "-Fn")
			if err == nil {
				for _, line := range strings.Split(string(output), "\n") {
					if strings.HasPrefix(line, "n") {
						p.Directory = line[1:]
					}
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
	output, err := commandOutput(ctx, "/usr/sbin/netstat", "-anv", "-p", "tcp")
	return err == nil && tcpListenerOwned(bytes.NewReader(output), p.PID, target) && Valid(p)
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxNativeReadBytes+1))
	if len(data) > maxNativeReadBytes {
		command.Process.Kill()
		command.Wait()
		return nil, io.ErrShortBuffer
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, readErr
	}
	return data, waitErr
}

func observedIPC(ctx context.Context, targets map[int]bool) (map[int][]string, error) {
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(deadline, "/usr/sbin/netstat", "-anv", "-f", "unix")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	listeners, readErr := unixListeners(stdout, targets)
	if readErr != nil {
		command.Process.Kill()
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return listeners, nil
}

func unixListeners(input io.Reader, targets map[int]bool) (map[int][]string, error) {
	result := make(map[int][]string)
	seen := make(map[string]bool)
	typeIndex, connectionIndex, pidIndex, pathIndex := -1, -1, -1, -1
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 0 && fields[0] == "Address" {
			typeIndex, connectionIndex, pathIndex = slices.Index(fields, "Type"), slices.Index(fields, "Conn"), slices.Index(fields, "Addr")
			pidIndex = slices.IndexFunc(fields, func(value string) bool { return value == "pid" || strings.HasSuffix(value, ":pid") })
			continue
		}
		if min(typeIndex, connectionIndex, pidIndex, pathIndex) < 0 || len(fields) <= max(typeIndex, connectionIndex, pidIndex, pathIndex) ||
			fields[typeIndex] != "stream" || fields[connectionIndex] != "0" {
			continue
		}
		owner := fields[pidIndex]
		pid, err := strconv.Atoi(owner[strings.LastIndexByte(owner, ':')+1:])
		if err != nil || !targets[pid] {
			continue
		}
		// The header identifies the path column; retain spaces within the unescaped path.
		path := line
		for range pathIndex {
			path = strings.TrimLeftFunc(path, unicode.IsSpace)
			at := strings.IndexFunc(path, unicode.IsSpace)
			if at < 0 {
				path = ""
				break
			}
			path = path[at:]
		}
		path = strings.TrimLeftFunc(path, unicode.IsSpace)
		key := strconv.Itoa(pid) + "\x00" + path
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r") || len(path) >= len(unix.RawSockaddrUnix{}.Path) || seen[key] {
			continue
		}
		seen[key] = true
		result[pid] = append(result[pid], path)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if min(typeIndex, connectionIndex, pidIndex, pathIndex) < 0 {
		return nil, errors.New("native socket inventory has no complete owner/path columns")
	}
	return result, nil
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
