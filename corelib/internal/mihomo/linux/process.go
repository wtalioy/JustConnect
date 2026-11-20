//go:build linux

package linux

import (
	"bufio"
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

const (
	procPath           = "/proc"
	procNetUnix        = procPath + "/net/unix"
	maxNativeReadBytes = 1 << 20
	// Unix domain socket states from /proc/net/unix: TCP_LISTEN marks a listener.
	unixStateListen = "0A"
	unixTypeStream  = "0002"
	unixPathLimit   = 108 // sizeof(struct sockaddr_un)::sun_path
)

// procID is one process identity fact kept local to this package.
type procID struct {
	pid       int
	uid       uint32
	startTime uint64
}

// Valid re-reads the process start time; PID reuse or exit invalidates ownership.
func Valid(p model.Process) bool {
	current, err := readProcID(p.PID)
	return err == nil && current.startTime == p.Started
}

func readProcID(pid int) (procID, error) {
	stat, err := os.ReadFile(statPath(pid))
	if err != nil {
		return procID{}, err
	}
	startTime, err := procStartTime(stat)
	if err != nil {
		return procID{}, err
	}
	info, err := os.Stat(pidPath(pid))
	if err != nil {
		return procID{}, err
	}
	stat_t, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return procID{}, errors.New("process identity is unavailable")
	}
	return procID{pid: pid, uid: stat_t.Uid, startTime: startTime}, nil
}

// procStartTime reads field 22 of /proc/<pid>/stat in clock ticks. The command
// name inside parentheses may contain spaces, so counting resumes after the
// final closing parenthesis.
func procStartTime(stat []byte) (uint64, error) {
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return 0, errors.New("malformed process stat entry")
	}
	fields := strings.Fields(string(stat[end+1:]))
	// Fields 3..N follow; start time is field 22, so index 19 after the name.
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, errors.New("process stat entry is truncated")
	}
	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
}

// Read enumerates recognized controller processes. Facts stay readable-by-owner:
// command lines, working directories and IPC listeners belong to the current
// user; cross-UID matches expose only public identity metadata.
func Read(ctx context.Context) ([]model.Process, error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	var result []model.Process
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		current, err := readProcID(pid)
		if err != nil {
			continue
		}
		own := current.uid == uint32(os.Getuid())
		if !recognizedComm(pid) && !(own && recognizedExe(pid)) {
			continue
		}
		p := model.Process{PID: pid, Started: current.startTime, NetworkAdmin: current.uid == 0}
		if own {
			if data, err := os.ReadFile(cmdlinePath(pid)); err == nil && len(data) <= maxNativeReadBytes {
				p.Args = splitNul(data)
			}
			if directory, err := os.Readlink(cwdPath(pid)); err == nil {
				p.Directory = directory
			}
			p.Home = home
			p.IPC = observedIPC(pid)
		}
		if Valid(p) {
			result = append(result, p)
		}
	}
	return result, nil
}

func recognizedComm(pid int) bool {
	data, err := os.ReadFile(commPath(pid))
	if err != nil {
		return false
	}
	return model.Recognized(strings.TrimRight(string(data), "\n"))
}

func recognizedExe(pid int) bool {
	target, err := os.Readlink(exePath(pid))
	if err != nil {
		return false
	}
	return model.Recognized(target)
}

func splitNul(data []byte) []string {
	var result []string
	for _, part := range strings.Split(string(data), "\x00") {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// observedIPC maps the process's stream listener inodes to their socket paths.
// Attribution stays owner-only: /proc/<pid>/fd is unreadable across users.
func observedIPC(pid int) []string {
	inodes, err := processSocketInodes(pid)
	if err != nil || len(inodes) == 0 {
		return nil
	}
	paths, err := unixListenerPaths()
	if err != nil {
		return nil
	}
	var result []string
	for inode, path := range paths {
		if inodes[inode] {
			result = append(result, path)
		}
	}
	sort.Strings(result)
	return result
}

// unixListenerPaths reads /proc/net/unix: listening stream sockets carry the
// TCP_LISTEN state and expose their public path column to every user. The path
// column is unquoted, so column splitting stops after the fixed fields.
func unixListenerPaths() (map[int]string, error) {
	file, err := os.Open(procNetUnix)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[int]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimLeft(scanner.Text(), " ")
		const fixedFields = 8
		fields, path := splitFields(line, fixedFields)
		if len(fields) < fixedFields || fields[4] != unixTypeStream || fields[5] != unixStateListen {
			continue
		}
		inode, err := strconv.Atoi(fields[6])
		if err != nil || inode <= 0 {
			continue
		}
		path = strings.TrimSpace(path)
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") || len(path) >= unixPathLimit {
			continue
		}
		result[inode] = path
	}
	return result, scanner.Err()
}

// splitFields consumes count space-separated tokens and returns them plus the
// unsplit remainder.
func splitFields(line string, count int) ([]string, string) {
	fields := make([]string, 0, count)
	remainder := line
	for range count {
		token, rest, found := strings.Cut(remainder, " ")
		if !found {
			return fields, ""
		}
		fields = append(fields, token)
		remainder = strings.TrimLeft(rest, " ")
	}
	return fields, remainder
}

func processSocketInodes(pid int) (map[int]bool, error) {
	descriptors, err := os.ReadDir(fdPath(pid))
	if err != nil {
		return nil, err
	}
	inodes := make(map[int]bool)
	for _, descriptor := range descriptors {
		target, err := os.Readlink(fdEntryPath(pid, descriptor.Name()))
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok && strings.HasSuffix(inode, "]") {
			if value, err := strconv.Atoi(inode[:len(inode)-1]); err == nil && value > 0 {
				inodes[value] = true
			}
		}
	}
	return inodes, nil
}

func pidPath(pid int) string                   { return procPath + "/" + strconv.Itoa(pid) }
func statPath(pid int) string                  { return pidPath(pid) + "/stat" }
func commPath(pid int) string                  { return pidPath(pid) + "/comm" }
func cmdlinePath(pid int) string               { return pidPath(pid) + "/cmdline" }
func cwdPath(pid int) string                   { return pidPath(pid) + "/cwd" }
func exePath(pid int) string                   { return pidPath(pid) + "/exe" }
func fdPath(pid int) string                    { return pidPath(pid) + "/fd" }
func fdEntryPath(pid int, entry string) string { return fdPath(pid) + "/" + entry }
