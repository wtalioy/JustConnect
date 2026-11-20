//go:build linux

package networkstate

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/unix"
)

func ReadInterfaces() ([]model.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// Interface.Addrs performs a full kernel address dump on every call.
	messages, err := netlinkMessages(unix.RTM_GETADDR, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return interfaceSnapshot(interfaces, messages)
}

func interfaceSnapshot(interfaces []net.Interface, messages []syscall.NetlinkMessage) ([]model.Interface, error) {
	result := make([]model.Interface, len(interfaces))
	positions := make(map[int]int, len(interfaces))
	for i, iface := range interfaces {
		positions[iface.Index] = i
		result[i] = model.Interface{Index: iface.Index, Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0, Addresses: []string{}}
	}
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		data := message.Data
		if len(data) < unix.SizeofIfAddrmsg {
			return nil, fmt.Errorf("short netlink interface address message")
		}
		index := int(binary.NativeEndian.Uint32(data[4:8]))
		position, known := positions[index]
		if !known || (data[0] != unix.AF_INET && data[0] != unix.AF_INET6) {
			continue
		}
		var address, local []byte
		for attrs := data[unix.SizeofIfAddrmsg:]; len(attrs) > 0; {
			kind, value, rest, err := nextAttribute(attrs)
			if err != nil {
				return nil, err
			}
			attrs = rest
			switch kind {
			case unix.IFA_ADDRESS:
				address = value
			case unix.IFA_LOCAL:
				local = value
			}
		}
		// On a point-to-point link IFA_ADDRESS may identify the remote endpoint.
		if local != nil {
			address = local
		}
		if address == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(address)
		prefix := netip.PrefixFrom(ip, int(data[1]))
		if !ok || ip.Is4() != (data[0] == unix.AF_INET) || !prefix.IsValid() {
			return nil, fmt.Errorf("invalid netlink address for interface %d", index)
		}
		// Keep the IPv4 CIDR representation returned by net.Interface.Addrs.
		if ip.Is4In6() {
			prefix = netip.PrefixFrom(ip.Unmap(), max(0, prefix.Bits()-96))
		}
		result[position].Addresses = append(result[position].Addresses, prefix.String())
	}
	for i := range result {
		slices.Sort(result[i].Addresses)
	}
	return result, nil
}
