//go:build linux

package networkstate

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMultipathRouteReadsNestedGateways(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.2")
	second := netip.MustParseAddr("198.51.100.2")
	encodeHop := func(index uint32, flags byte, gateway netip.Addr) []byte {
		header := make([]byte, unix.SizeofRtNexthop)
		nested := append(encodeRouteAttribute(0, []byte{1}), encodeRouteAttribute(unix.RTA_GATEWAY, gateway.AsSlice())...)
		binary.NativeEndian.PutUint16(header, uint16(len(header)+len(nested)))
		header[2] = flags
		binary.NativeEndian.PutUint32(header[4:], index)
		return append(header, nested...)
	}
	value := append(encodeHop(2, unix.RTNH_F_LINKDOWN, first), encodeHop(3, 0, second)...)
	data := make([]byte, unix.SizeofRtMsg)
	data[0], data[rtFieldTable], data[rtFieldType] = unix.AF_INET, unix.RT_TABLE_MAIN, unix.RTN_UNICAST
	data = append(data, encodeRouteAttribute(0, []byte{1, 2, 3})...)
	data = append(data, encodeRouteAttribute(unix.RTA_MULTIPATH, value)...)
	message := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: data}
	row, err := parseRouteRow(message)
	want := []nexthop{{index: 2, flags: unix.RTNH_F_LINKDOWN, gateway: first}, {index: 3, gateway: second}}
	if err != nil || !slices.Equal(row.nexthops, want) {
		t.Fatalf("parseRouteRow() = %+v, %v, want %+v", row.nexthops, err, want)
	}
	if hops, err := parseNexthops(value[:len(value)-1]); hops != nil || err == nil {
		t.Fatalf("partially decoded a truncated multipath route: %+v, %v", hops, err)
	}
	message.Data = message.Data[:len(message.Data)-1]
	if _, err := parseRouteRow(message); err == nil {
		t.Fatal("accepted a route with a truncated attribute")
	}
}

func encodeRouteAttribute(kind uint16, value []byte) []byte {
	size := unix.SizeofRtAttr + len(value)
	attribute := make([]byte, (size+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(attribute, uint16(size))
	binary.NativeEndian.PutUint16(attribute[2:], kind)
	copy(attribute[unix.SizeofRtAttr:], value)
	return attribute
}
