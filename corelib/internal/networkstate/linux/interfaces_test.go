//go:build linux

package networkstate

import (
	"encoding/binary"
	"net"
	"net/netip"
	"reflect"
	"syscall"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"golang.org/x/sys/unix"
)

func interfaceAddress(index int, prefix string, local string) syscall.NetlinkMessage {
	address := netip.MustParsePrefix(prefix)
	data := make([]byte, unix.SizeofIfAddrmsg)
	data[0], data[1] = unix.AF_INET6, byte(address.Bits())
	if address.Addr().Is4() {
		data[0] = unix.AF_INET
	}
	binary.NativeEndian.PutUint32(data[4:], uint32(index))
	data = append(data, encodeRouteAttribute(unix.IFA_ADDRESS, address.Addr().AsSlice())...)
	if local != "" {
		data = append(data, encodeRouteAttribute(unix.IFA_LOCAL, netip.MustParseAddr(local).AsSlice())...)
	}
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWADDR}, Data: data}
}

func TestInterfaceSnapshot(t *testing.T) {
	links := []net.Interface{
		{Index: 5, Name: "p2p", Flags: net.FlagUp | net.FlagPointToPoint},
		{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		{Index: 8, Name: "idle"},
	}
	rows := []syscall.NetlinkMessage{
		interfaceAddress(5, "2001:db8::10/64", ""),
		interfaceAddress(5, "192.0.2.2/32", "192.0.2.1"),
		interfaceAddress(5, "::ffff:198.51.100.5/120", ""),
		interfaceAddress(1, "127.0.0.1/8", ""),
		interfaceAddress(12, "203.0.113.7/24", ""),
		{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}},
	}
	want := []model.Interface{
		{Index: 5, Name: "p2p", Up: true, Addresses: []string{"192.0.2.1/32", "198.51.100.5/24", "2001:db8::10/64"}},
		{Index: 1, Name: "lo", Up: true, Loopback: true, Addresses: []string{"127.0.0.1/8"}},
		{Index: 8, Name: "idle", Addresses: []string{}},
	}
	got, err := interfaceSnapshot(links, rows)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("interfaceSnapshot() = %+v, %v, want %+v", got, err, want)
	}

	rows[0].Data = rows[0].Data[:4]
	if got, err := interfaceSnapshot(links, rows); got != nil || err == nil {
		t.Fatalf("short message should reject the snapshot, got %+v, %v", got, err)
	}
}
