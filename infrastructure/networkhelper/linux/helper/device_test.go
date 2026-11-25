//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidateIPv4Unicast(t *testing.T) {
	accept := []string{"10.22.4.1", "1.2.3.4", "223.255.255.1", "59.64.0.1"}
	for _, text := range accept {
		if _, err := validateIPv4Unicast(text); err != nil {
			t.Fatalf("%s rejected: %v", text, err)
		}
	}
	reject := []string{"127.0.0.1", "224.0.0.1", "0.0.0.0", "1.2.3.4.5",
		"::ffff:10.0.0.1", "::1", "example.invalid", "", "255.255.255.255"}
	for _, text := range reject {
		if _, err := validateIPv4Unicast(text); err == nil {
			t.Fatalf("%s accepted", text)
		}
	}
}

func TestValidatePrefix(t *testing.T) {
	prefix, err := validatePrefix("10.50.0.0/16")
	if err != nil {
		t.Fatalf("valid prefix rejected: %v", err)
	}
	if prefix.Bits() != 16 || !prefix.Addr().Is4() {
		t.Fatalf("unexpected prefix %v", prefix)
	}
	reject := []string{"10.50.1.0/16", "::ffff:10.0.0.0/120", "10.0.0.0/33", "example/8", "10.0.0.1"}
	for _, text := range reject {
		if _, err := validatePrefix(text); err == nil {
			t.Fatalf("%s accepted", text)
		}
	}
}

func TestNetlinkAttrAlignment(t *testing.T) {
	for size := 1; size <= 5; size++ {
		attr := netlinkAttr(7, make([]byte, size))
		if len(attr) != align4(4+size) {
			t.Fatalf("attr payload %d produced unaligned length %d", size, len(attr))
		}
		if got := binary.LittleEndian.Uint16(attr[0:2]); int(got) != 4+size {
			t.Fatalf("attr length %d, expected %d", got, 4+size)
		}
		if got := binary.LittleEndian.Uint16(attr[2:4]); got != 7 {
			t.Fatalf("attr type %d, expected 7", got)
		}
	}
}

// encodeAddressRow builds one synthetic RTM_NEWADDR record.
func encodeAddressRow(index int, local, peer netip.Addr) []byte {
	var header [16]byte
	binary.LittleEndian.PutUint16(header[4:6], unix.RTM_NEWADDR)
	row := []byte{unix.AF_INET, 32, unix.IFA_F_PERMANENT, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(row[4:8], uint32(index))
	localOctets := local.As4()
	peerOctets := peer.As4()
	localAttr := netlinkAttr(unix.IFA_LOCAL, localOctets[:])
	peerAttr := netlinkAttr(unix.IFA_ADDRESS, peerOctets[:])
	record := append(row[:], localAttr...)
	record = append(record, peerAttr...)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(record)))
	return append(header[:], record...)
}

func TestFindAddressPair(t *testing.T) {
	local := netip.MustParseAddr("10.22.4.1")
	peer := netip.MustParseAddr("10.22.4.2")
	rib := encodeAddressRow(9, local, peer)
	if !findAddressPair(rib, 9, local, peer) {
		t.Fatal("configured pair not found")
	}
	if findAddressPair(rib, 10, local, peer) {
		t.Fatal("pair found on the wrong interface")
	}
	if findAddressPair(rib, 9, peer, local) {
		t.Fatal("reversed pair accepted")
	}
}

func TestDumpRoutesParsesDeviceRoutes(t *testing.T) {
	var header [16]byte
	binary.LittleEndian.PutUint16(header[4:6], unix.RTM_NEWROUTE)
	dst := netip.MustParseAddr("10.50.0.0")
	rt := routePayload(16, unix.RT_TABLE_MAIN)
	rt[0] = unix.AF_INET
	dstOctets := dst.As4()
	attrs := netlinkAttr(unix.RTA_DST, dstOctets[:])
	attrs = append(attrs, u32attr(unix.RTA_OIF, 9)...)
	record := append(rt, attrs...)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(record)))
	rib := append(append(header[:], record...), encodeRouteRow(7, dst, 16, unix.RT_TABLE_MAIN)...)

	targets, err := dumpRoutes(rib, 9)
	if err != nil {
		t.Fatalf("dumpRoutes: %v", err)
	}
	if len(targets) != 1 || targets[0].table != unix.RT_TABLE_MAIN ||
		!targets[0].hasDst || targets[0].dst != dst || targets[0].dstLen != 16 {
		t.Fatalf("unexpected targets %+v", targets)
	}
	if targets, err := dumpRoutes(rib, 7); err != nil || len(targets) != 1 {
		t.Fatalf("second row missing: %v %+v", err, targets)
	}
}

// encodeRouteRow builds one synthetic RTM_NEWROUTE record.
func encodeRouteRow(index int, dst netip.Addr, bits, table byte) []byte {
	var header [16]byte
	binary.LittleEndian.PutUint16(header[4:6], unix.RTM_NEWROUTE)
	rt := routePayload(bits, table)
	rt[0] = unix.AF_INET
	dstOctets := dst.As4()
	attrs := netlinkAttr(unix.RTA_DST, dstOctets[:])
	attrs = append(attrs, u32attr(unix.RTA_OIF, uint32(index))...)
	record := append(rt, attrs...)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(record)))
	return append(header[:], record...)
}

func TestRoutePayloadShape(t *testing.T) {
	payload := routePayload(24, unix.RT_TABLE_MAIN)
	if payload[0] != unix.AF_INET || payload[1] != 24 {
		t.Fatalf("unexpected family/dst_len: %v", payload)
	}
	if payload[4] != unix.RT_TABLE_MAIN || payload[5] != unix.RTPROT_STATIC {
		t.Fatalf("unexpected table/protocol: %v", payload)
	}
	if payload[6] != unix.RT_SCOPE_LINK || payload[7] != unix.RTN_UNICAST {
		t.Fatalf("unexpected scope/type: %v", payload)
	}
}

// Exclusive adds replace nothing: a row installed by another tool must
// survive connect and disconnect, so the request carries EXCL and never
// REPLACE, and collisions are resolved by ownership verification.
func TestRouteAddFlagsAreExclusive(t *testing.T) {
	if routeAddFlags&unix.NLM_F_REPLACE != 0 {
		t.Fatal("route adds carry NLM_F_REPLACE and would replace foreign routes")
	}
	if routeAddFlags&unix.NLM_F_EXCL == 0 || routeAddFlags&unix.NLM_F_CREATE == 0 {
		t.Fatal("route adds must request an exclusive create")
	}
}

func TestRouteOwnedVerifiesCollisionOwnership(t *testing.T) {
	dst := netip.MustParseAddr("10.50.0.0")
	prefix := netip.PrefixFrom(dst, 16)
	owned := []byte(nil)
	owned = append(owned, encodeRouteRow(9, dst, 16, unix.RT_TABLE_MAIN)...)
	if !routeOwned(owned, 9, prefix) {
		t.Fatal("the helper's own leftover row is not recognized as owned")
	}

	// A foreign route to the same destination on another interface: the
	// collision must not be accepted as owned.
	foreign := []byte(encodeRouteRow(7, dst, 16, unix.RT_TABLE_MAIN))
	if routeOwned(foreign, 9, prefix) {
		t.Fatal("a foreign route on another interface was accepted as owned")
	}

	// Same device, different destination length: not the same row.
	wider := []byte(encodeRouteRow(9, dst, 8, unix.RT_TABLE_MAIN))
	if routeOwned(wider, 9, prefix) {
		t.Fatal("a different prefix length was accepted as owned")
	}

	// Same device and destination but a non-main table: sweepRoutes only
	// removes rows the dump attributes to the device, and this one lives in a
	// table the helper never writes.
	otherTable := []byte(encodeRouteRow(9, dst, 16, 42))
	if routeOwned(otherTable, 9, prefix) {
		t.Fatal("a route in another table was accepted as owned")
	}

	// A default route pointing at the device carries no destination; it must
	// not shadow the owned row that follows it in the same dump.
	var header [16]byte
	binary.LittleEndian.PutUint16(header[4:6], unix.RTM_NEWROUTE)
	rt := routePayload(0, unix.RT_TABLE_MAIN)
	rt[0] = unix.AF_INET
	record := append(rt[:], u32attr(unix.RTA_OIF, 9)...)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(record)))
	rib := append(append(header[:], record...), encodeRouteRow(9, dst, 16, unix.RT_TABLE_MAIN)...)
	if !routeOwned(rib, 9, prefix) {
		t.Fatal("a destination-less route hid the helper's own row")
	}

	// No matching row at all: a collision the helper cannot attribute.
	if routeOwned([]byte(encodeRouteRow(9, netip.MustParseAddr("10.60.0.0"), 16, unix.RT_TABLE_MAIN)), 9, prefix) {
		t.Fatal("a different destination was accepted as owned")
	}
}
