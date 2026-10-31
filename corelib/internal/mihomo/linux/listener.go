//go:build linux

package linux

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

// ListenerInode is visible without ptrace access to a privileged process's fd table.
func ListenerInode(ctx context.Context, target netip.AddrPort) uint64 {
	for _, name := range []string{"tcp", "tcp6"} {
		if ctx.Err() != nil {
			return 0
		}
		file, err := os.Open("/proc/net/" + name)
		if err != nil {
			continue
		}
		inode := scanListener(ctx, file, target)
		file.Close()
		if inode != 0 {
			return inode
		}
	}
	return 0
}
func scanListener(ctx context.Context, file *os.File, target netip.AddrPort) uint64 {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return 0
		}
		fields := strings.Fields(scanner.Text())
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
		for offset := 0; offset < len(bytes); offset += 4 {
			bytes[offset], bytes[offset+3] = bytes[offset+3], bytes[offset]
			bytes[offset+1], bytes[offset+2] = bytes[offset+2], bytes[offset+1]
		}
		address, ok := netip.AddrFromSlice(bytes)
		if ok && model.ListenerMatches(address, target.Addr()) {
			inode, _ := strconv.ParseUint(fields[9], 10, 64)
			return inode
		}
	}
	return 0
}

func NeedsProof(ctx context.Context, p model.Process, target netip.AddrPort) bool {
	_, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(p.PID), "fd"))
	return errors.Is(err, os.ErrPermission) && Valid(p) && ListenerInode(ctx, target) != 0
}

// ListenerUnchanged revalidates a previously attested process/socket without scanning its fd table.
func ListenerUnchanged(ctx context.Context, process model.Process, target netip.AddrPort, inode uint64) bool {
	return inode != 0 && Valid(process) && ListenerInode(ctx, target) == inode
}
