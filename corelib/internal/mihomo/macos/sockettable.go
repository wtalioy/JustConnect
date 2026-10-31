package macos

import (
	"bufio"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

// netstat's kernel socket inventory includes cross-user PIDs without proc_pidfdinfo privileges.
func tcpListenerOwned(input io.Reader, pid int, target netip.AddrPort) bool {
	if pid <= 0 || !target.Addr().IsLoopback() || target.Port() == 0 {
		return false
	}
	scanner := bufio.NewScanner(input)
	local, state, owner, columns := -1, -1, -1, 0
	// Read the whole inventory so a newline in a process name cannot inject a partial row.
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || columns == 0 && strings.HasPrefix(line, "Active Internet connections") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "Proto ") {
			if columns != 0 {
				return false
			}
			line = strings.ReplaceAll(strings.ReplaceAll(line, "Local Address", "LocalAddress"), "Foreign Address", "ForeignAddress")
			header := strings.Fields(line)
			local, state = slices.Index(header, "LocalAddress"), slices.Index(header, "(state)")
			owner = slices.IndexFunc(header, func(value string) bool { return value == "pid" || strings.HasSuffix(value, ":pid") })
			if min(local, state, owner) < 0 {
				return false
			}
			columns = len(header)
			continue
		}
		if strings.HasPrefix(line, "Some tcp sockets may have been ") {
			continue
		}
		fields := strings.Fields(line)
		if columns == 0 || len(fields) < columns || !slices.Contains([]string{"tcp4", "tcp6", "tcp46"}, fields[0]) {
			return false
		}
		if fields[state] != "LISTEN" {
			continue
		}
		// Names can contain spaces; the kernel PID is followed by fixed numeric columns.
		identity := fields[len(fields)-(columns-owner)]
		observed, err := strconv.Atoi(identity[strings.LastIndexByte(identity, ':')+1:])
		if err != nil || observed != pid {
			continue
		}
		endpoint := fields[local]
		separator := strings.LastIndexByte(endpoint, '.')
		if separator < 0 {
			continue
		}
		port, err := strconv.ParseUint(endpoint[separator+1:], 10, 16)
		if err != nil || uint16(port) != target.Port() {
			continue
		}
		host := endpoint[:separator]
		if host == "*" {
			if fields[0] == "tcp46" || fields[0] == "tcp4" && target.Addr().Is4() || fields[0] == "tcp6" && target.Addr().Is6() {
				found = true
			}
			continue
		}
		address, err := netip.ParseAddr(host)
		if err == nil && model.ListenerMatches(address, target.Addr()) {
			found = true
		}
	}
	return found && scanner.Err() == nil
}
