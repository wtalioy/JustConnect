//go:build linux

// Device management for the privileged helper: TUN creation, addresses, MTU
// and routes. The constructed device must satisfy every check in
// corelib/internal/tundevice/linux/tun.go because the JustConnect process
// hands the descriptor straight to the core, which re-validates it: an
// IPv4-only, headerless (IFF_TUN|IFF_NO_PI), nonblocking descriptor backed by
// an up interface with an exact MTU and a distinct point-to-point address
// pair (IFA_LOCAL + IFA_ADDRESS).
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// tunDevice owns the raw TUN file descriptor created for one session plus the
// netlink socket used to configure it.
type tunDevice struct {
	name  string
	index int
	fd    int
	local netip.Addr
	peer  netip.Addr
	mtu   int
	nl    netlinkMutator
}

// netlinkMutator is the device-facing subset of the NETLINK_ROUTE connection.
// The indirection lets unit tests fake the kernel side (route failures,
// sweep verification) without a real TUN device.
type netlinkMutator interface {
	linkSetMTUUp(index, mtu int) error
	addAddress(index int, local, peer netip.Addr) error
	addRoute(index int, prefix netip.Prefix) error
	delRoute(index int, prefix netip.Prefix) error
	sweepRoutes(index int) error
	delAddress(index int, local, peer netip.Addr) error
	linkDown(index int) error
}

// openTUN creates a fresh nonpersistent TUN device. The kernel chooses the
// tun<N> name, matching the naming the core's tunnel observer expects.
func openTUN() (*tunDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	request, err := unix.NewIfreq("")
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	request.SetUint32(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	name := request.Name()
	if name == "" {
		unix.Close(fd)
		return nil, errors.New("kernel assigned an empty TUN device name")
	}
	if err := verifyTUNFlags(fd, name); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set TUN nonblocking: %w", err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("look up %s: %w", name, err)
	}
	nl, err := openNetlink()
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &tunDevice{name: name, index: iface.Index, fd: fd, mtu: iface.MTU, nl: nl}, nil
}

// verifyTUNFlags mirrors the core's TUNGETIFF read-back so a broken kernel or
// wrapper is caught here instead of failing the core attach.
func verifyTUNFlags(fd int, name string) error {
	request, err := unix.NewIfreq("")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, request); err != nil {
		return fmt.Errorf("TUNGETIFF: %w", err)
	}
	if got := request.Name(); got != name {
		return fmt.Errorf("kernel reported device %q, expected %q", got, name)
	}
	flags := request.Uint32()
	required := uint32(unix.IFF_TUN | unix.IFF_NO_PI)
	forbidden := uint32(unix.IFF_TAP | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
	if flags&forbidden != 0 || flags&required != required {
		return fmt.Errorf("device flags %#x violate the IPv4 headerless TUN contract", flags)
	}
	return nil
}

// configure applies the MTU, brings the interface up and installs the
// point-to-point address pair, then verifies every value the core will
// re-check during attach.
func (d *tunDevice) configure(local, peer netip.Addr, mtu int) error {
	if err := d.nl.linkSetMTUUp(d.index, mtu); err != nil {
		return err
	}
	if err := d.nl.addAddress(d.index, local, peer); err != nil {
		return err
	}
	d.local, d.peer, d.mtu = local, peer, mtu
	return d.verifyConfigured()
}

func (d *tunDevice) verifyConfigured() error {
	iface, err := net.InterfaceByName(d.name)
	if err != nil {
		return fmt.Errorf("look up %s after configuration: %w", d.name, err)
	}
	if iface.MTU != d.mtu {
		return fmt.Errorf("interface %s reports mtu %d, expected %d", d.name, iface.MTU, d.mtu)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s did not come up", d.name)
	}
	rib, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("dump addresses: %w", err)
	}
	if !findAddressPair(rib, d.index, d.local, d.peer) {
		return fmt.Errorf("interface %s does not report the configured point-to-point pair %s/%s",
			d.name, d.local, d.peer)
	}
	return nil
}

// withdraw removes every route, address and up-flag owned by the device. The
// nonpersistent device disappears once this helper releases its descriptor.
func (d *tunDevice) withdraw() error {
	var problems []string
	if err := d.nl.sweepRoutes(d.index); err != nil {
		problems = append(problems, err.Error())
	}
	if d.local.IsValid() {
		if err := d.nl.delAddress(d.index, d.local, d.peer); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if err := d.nl.linkDown(d.index); err != nil {
		problems = append(problems, err.Error())
	}
	d.close()
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func (d *tunDevice) close() {
	if conn, ok := d.nl.(*netlinkConn); ok {
		conn.close()
	}
	d.nl = nil
	if d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
	}
}

// netlinkConn is a NETLINK_ROUTE socket for one device's mutations.
type netlinkConn struct {
	fd    int
	write uint32
}

func openNetlink() (*netlinkConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open netlink route socket: %w", err)
	}
	return &netlinkConn{fd: fd}, nil
}

func (c *netlinkConn) close() {
	unix.Close(c.fd)
	c.fd = -1
}

func align4(n int) int { return (n + 3) &^ 3 }

// netlinkAttr encodes one aligned rtattr payload.
func netlinkAttr(typ uint16, data []byte) []byte {
	length := 4 + len(data)
	attr := make([]byte, 4, align4(length))
	binary.LittleEndian.PutUint16(attr[0:2], uint16(length))
	binary.LittleEndian.PutUint16(attr[2:4], typ)
	attr = append(attr, data...)
	for len(attr) < align4(length) {
		attr = append(attr, 0)
	}
	return attr
}

func u32attr(typ uint16, value uint32) []byte {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	return netlinkAttr(typ, data[:])
}

func ip4attr(typ uint16, addr netip.Addr) []byte {
	octets := addr.As4()
	return netlinkAttr(typ, octets[:])
}

// netlinkMessage frames one request; the fixed payloads (ifinfomsg,
// ifaddrmsg, rtmsg) are all 4-byte aligned so attributes stay aligned too.
func netlinkMessage(typ uint16, flags uint16, seq uint32, payload []byte, attrs []byte) []byte {
	body := make([]byte, 0, len(payload)+len(attrs))
	body = append(body, payload...)
	body = append(body, attrs...)
	msg := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(msg[4:6], typ)
	binary.LittleEndian.PutUint16(msg[6:8], flags)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	return append(msg, body...)
}

func (c *netlinkConn) nextSeq() uint32 {
	c.write++
	return c.write
}

// transact sends one request and waits for the matching ACK or error.
func (c *netlinkConn) transact(label string, msg []byte) error {
	to := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(c.fd, msg, 0, to); err != nil {
		return fmt.Errorf("send %s: %w", label, err)
	}
	seq := binary.LittleEndian.Uint32(msg[8:12])
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("receive %s reply: %w", label, err)
		}
		if n < 16 {
			return fmt.Errorf("short %s reply", label)
		}
		if binary.LittleEndian.Uint32(buf[8:12]) != seq {
			continue
		}
		length := int(binary.LittleEndian.Uint32(buf[0:4]))
		switch binary.LittleEndian.Uint16(buf[4:6]) {
		case unix.NLMSG_ERROR:
			if length < 20 {
				return fmt.Errorf("short %s error reply", label)
			}
			code := int32(binary.LittleEndian.Uint32(buf[16:20]))
			if code == 0 {
				return nil
			}
			return fmt.Errorf("%s: %w", label, unix.Errno(-code))
		default:
			if length < 16 || length > n {
				return fmt.Errorf("malformed %s reply", label)
			}
		}
	}
}

func (c *netlinkConn) linkSetMTUUp(index, mtu int) error {
	var info [16]byte
	binary.LittleEndian.PutUint32(info[4:8], uint32(index))
	binary.LittleEndian.PutUint32(info[8:12], unix.IFF_UP)
	binary.LittleEndian.PutUint32(info[12:16], unix.IFF_UP)
	msg := netlinkMessage(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, c.nextSeq(), info[:],
		u32attr(unix.IFLA_MTU, uint32(mtu)))
	return c.transact("link mtu/up", msg)
}

func (c *netlinkConn) linkDown(index int) error {
	var info [16]byte
	binary.LittleEndian.PutUint32(info[4:8], uint32(index))
	binary.LittleEndian.PutUint32(info[12:16], unix.IFF_UP)
	msg := netlinkMessage(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, c.nextSeq(), info[:], nil)
	err := c.transact("link down", msg)
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func addressPayload(index int) []byte {
	var addr [8]byte
	addr[0] = unix.AF_INET
	addr[1] = 32
	addr[2] = unix.IFA_F_PERMANENT
	addr[3] = unix.RT_SCOPE_UNIVERSE
	binary.LittleEndian.PutUint32(addr[4:8], uint32(index))
	return addr[:]
}

func (c *netlinkConn) addAddress(index int, local, peer netip.Addr) error {
	attrs := append(ip4attr(unix.IFA_LOCAL, local), ip4attr(unix.IFA_ADDRESS, peer)...)
	msg := netlinkMessage(unix.RTM_NEWADDR,
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, c.nextSeq(), addressPayload(index), attrs)
	err := c.transact("address add", msg)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (c *netlinkConn) delAddress(index int, local, peer netip.Addr) error {
	attrs := append(ip4attr(unix.IFA_LOCAL, local), ip4attr(unix.IFA_ADDRESS, peer)...)
	msg := netlinkMessage(unix.RTM_DELADDR, unix.NLM_F_REQUEST|unix.NLM_F_ACK, c.nextSeq(), addressPayload(index), attrs)
	err := c.transact("address del", msg)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}

func routePayload(dstLen, table byte) []byte {
	var rt [12]byte
	rt[0] = unix.AF_INET
	rt[1] = dstLen
	rt[4] = table
	rt[5] = unix.RTPROT_STATIC
	rt[6] = unix.RT_SCOPE_LINK
	rt[7] = unix.RTN_UNICAST
	return rt[:]
}

// deleteRoutePayload frames an RTM_DELROUTE request. Deletion must not constrain
// protocol, scope or type: the kernel-owned connected routes of the point-to-point
// address pair (RTPROT_KERNEL, scope host, RTN_LOCAL) describe the same
// destination and interface as the helper-installed campus routes with entirely
// different metadata, and fib_table_delete only matches a field the request
// actually sets. Leaving them unspecified deletes any route with the same
// destination, table and interface — every route this sweep owns.
func deleteRoutePayload(dstLen, table byte) []byte {
	var rt [12]byte
	rt[0] = unix.AF_INET
	rt[1] = dstLen
	rt[4] = table
	rt[6] = unix.RT_SCOPE_NOWHERE
	return rt[:]
}

// routeAddFlags frames the RTM_NEWROUTE request. Exclusive: the helper must
// never silently replace a row another tool installed; a collision surfaces
// as EEXIST and is resolved by ownership verification below.
const routeAddFlags = unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL

func (c *netlinkConn) addRoute(index int, prefix netip.Prefix) error {
	attrs := append(ip4attr(unix.RTA_DST, prefix.Addr()),
		u32attr(unix.RTA_OIF, uint32(index))...)
	msg := netlinkMessage(unix.RTM_NEWROUTE, routeAddFlags,
		c.nextSeq(), routePayload(byte(prefix.Bits()), unix.RT_TABLE_MAIN), attrs)
	err := c.transact("route add "+prefix.String(), msg)
	if !errors.Is(err, unix.EEXIST) {
		return err
	}
	// A route to this destination already exists. It may only be the helper's
	// own leftover row (same destination, main table, pointing at the owned
	// device — exactly what sweepRoutes removes), so re-connecting after a
	// crash succeeds. A route added by another tool must survive connect and
	// disconnect: the collision fails instead of replacing or sweeping it.
	rib, dumpErr := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if dumpErr != nil {
		return fmt.Errorf("route add %s: inspect the conflicting route: %w", prefix, dumpErr)
	}
	if routeOwned(rib, index, prefix) {
		return nil
	}
	return fmt.Errorf("route add %s: destination already routed by another owner and was left untouched", prefix)
}

// routeOwned reports whether the RIB holds a main-table route for exactly
// prefix whose outbound interface is the owned device — a row the helper
// installed (or inherited from its own crashed instance).
func routeOwned(rib []byte, index int, prefix netip.Prefix) bool {
	targets, err := dumpRoutes(rib, index)
	if err != nil {
		return false
	}
	for _, target := range targets {
		if target.table == unix.RT_TABLE_MAIN && target.hasDst &&
			netip.PrefixFrom(target.dst, int(target.dstLen)) == prefix {
			return true
		}
	}
	return false
}

func (c *netlinkConn) delRoute(index int, prefix netip.Prefix) error {
	attrs := append(ip4attr(unix.RTA_DST, prefix.Addr()),
		u32attr(unix.RTA_OIF, uint32(index))...)
	msg := netlinkMessage(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, c.nextSeq(),
		deleteRoutePayload(byte(prefix.Bits()), unix.RT_TABLE_MAIN), attrs)
	err := c.transact("route del "+prefix.String(), msg)
	return tolerateMissingRoute(err)
}

func tolerateMissingRoute(err error) error {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}

// routeTarget is one deletable route row pointing at the owned device.
type routeTarget struct {
	dst    netip.Addr
	hasDst bool
	dstLen byte
	table  byte
}

// dumpRoutes lists every IPv4 route in one RIB dump whose outbound interface
// is index.
func dumpRoutes(rib []byte, index int) ([]routeTarget, error) {
	var targets []routeTarget
	for offset := 0; len(rib)-offset >= 16; {
		length := int(binary.LittleEndian.Uint32(rib[offset : offset+4]))
		if length < 16 || offset+length > len(rib) {
			return nil, errors.New("malformed route dump")
		}
		if binary.LittleEndian.Uint16(rib[offset+4:offset+6]) == unix.RTM_NEWROUTE {
			row := rib[offset+16 : offset+length]
			if len(row) >= 12 && row[0] == unix.AF_INET {
				var oif uint32
				var target routeTarget
				target.table = row[4]
				target.dstLen = row[1]
				eachAttr(row[12:], func(typ uint16, data []byte) bool {
					switch typ {
					case unix.RTA_OIF:
						if len(data) == 4 {
							oif = binary.LittleEndian.Uint32(data)
						}
					case unix.RTA_DST:
						if len(data) == 4 {
							target.dst = netip.AddrFrom4([4]byte(data))
							target.hasDst = true
						}
					}
					return true
				})
				if oif == uint32(index) {
					targets = append(targets, target)
				}
			}
		}
		offset += align4(length)
	}
	return targets, nil
}

// sweepRoutes deletes every route pointing at the interface, retrying until
// the table is clean; the kernel resolves dependent routes in arbitrary order.
func (c *netlinkConn) sweepRoutes(index int) error {
	for pass := 0; pass < 4; pass++ {
		rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
		if err != nil {
			return fmt.Errorf("dump routes: %w", err)
		}
		targets, err := dumpRoutes(rib, index)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return nil
		}
		for _, target := range targets {
			attrs := []byte{}
			if target.hasDst {
				attrs = append(attrs, ip4attr(unix.RTA_DST, target.dst)...)
			}
			attrs = append(attrs, u32attr(unix.RTA_OIF, uint32(index))...)
			msg := netlinkMessage(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, c.nextSeq(),
				deleteRoutePayload(target.dstLen, target.table), attrs)
			if err := tolerateMissingRoute(c.transact("route sweep", msg)); err != nil {
				return err
			}
		}
	}
	rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("dump routes: %w", err)
	}
	targets, err := dumpRoutes(rib, index)
	if err != nil {
		return err
	}
	if len(targets) != 0 {
		return fmt.Errorf("%d route(s) still point at the owned interface", len(targets))
	}
	return nil
}

// eachAttr walks one netlink attribute region; returning false stops the walk.
func eachAttr(buf []byte, visit func(typ uint16, data []byte) bool) {
	for len(buf) >= 4 {
		length := int(binary.LittleEndian.Uint16(buf[0:2]))
		if length < 4 || length > len(buf) {
			return
		}
		if !visit(binary.LittleEndian.Uint16(buf[2:4]), buf[4:length]) {
			return
		}
		buf = buf[align4(length):]
	}
}

// findAddressPair mirrors the core's RTM_GETADDR check: the interface must
// report IFA_LOCAL and IFA_ADDRESS as a distinct point-to-point pair.
func findAddressPair(rib []byte, index int, local, peer netip.Addr) bool {
	for offset := 0; len(rib)-offset >= 16; {
		length := int(binary.LittleEndian.Uint32(rib[offset : offset+4]))
		if length < 16 || offset+length > len(rib) {
			return false
		}
		if binary.LittleEndian.Uint16(rib[offset+4:offset+6]) == unix.RTM_NEWADDR {
			row := rib[offset+16 : offset+length]
			if len(row) >= 8 && row[0] == unix.AF_INET && row[1] == 32 &&
				int(binary.LittleEndian.Uint32(row[4:8])) == index {
				var foundLocal, foundPeer bool
				eachAttr(row[8:], func(typ uint16, data []byte) bool {
					switch typ {
					case unix.IFA_LOCAL:
						if len(data) == 4 {
							foundLocal = netip.AddrFrom4([4]byte(data)) == local
						}
					case unix.IFA_ADDRESS:
						if len(data) == 4 {
							foundPeer = netip.AddrFrom4([4]byte(data)) == peer
						}
					}
					return true
				})
				if foundLocal && foundPeer {
					return true
				}
			}
		}
		offset += align4(length)
	}
	return false
}

// validateIPv4Unicast mirrors the core's ValidIPv4Pair address rules.
func validateIPv4Unicast(text string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", text)
	}
	if !addr.Is4() || addr.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%q is not a plain IPv4 address", text)
	}
	octets := addr.As4()
	if octets[0] < 1 || octets[0] > 223 || octets[0] == 127 {
		return netip.Addr{}, fmt.Errorf("%q is not a usable unicast IPv4 address", text)
	}
	return addr, nil
}

// validatePrefix accepts masked IPv4 prefixes only.
func validatePrefix(text string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a prefix", text)
	}
	if !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix.Bits() > 32 {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 prefix", text)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%q carries host bits", text)
	}
	return prefix, nil
}
