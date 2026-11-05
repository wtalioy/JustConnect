package ipresource

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/wtalioy/JustConnect/corelib/client"
)

type ipv4Range struct{ first, last uint32 }

const firstUnicastIPv4, lastUnicastIPv4 = 0x01000000, 0xdfffffff
const publicSubnetSize = 1 << (32 - 24)

// RFC 1918 scopes are the only implicit campus destinations for unscoped grants.
var privateRanges = [...]ipv4Range{
	{0x0a000000, 0x0affffff}, // 10.0.0.0/8
	{0xac100000, 0xac1fffff}, // 172.16.0.0/12
	{0xc0a80000, 0xc0a8ffff}, // 192.168.0.0/16
}

// ScopedRanges separates concrete campus ranges from grants covering the full
// IPv4 unicast space. A grant can leave holes in private subnets and omit
// individual public infrastructure hosts.
func ScopedRanges(resources []client.IPResource) ([]client.IPResource, [][2]netip.Addr) {
	type permission struct {
		app, node, protocol string
		firstPort, lastPort int
		l3                  bool
	}
	type interval struct {
		ipv4Range
		index int
	}
	groups := make(map[permission][]interval)
	for index, resource := range resources {
		first, firstOK := IPv4Uint32(resource.IPMin)
		last, lastOK := IPv4Uint32(resource.IPMax)
		if !firstOK || !lastOK || first > last || last < firstUnicastIPv4 || first > lastUnicastIPv4 || isPrivateRange(first, last) {
			continue
		}
		key := permission{resource.AppID, resource.NodeGroupID, resource.Protocol, resource.PortMin, resource.PortMax, resource.EnableTCPPrefL3}
		groups[key] = append(groups[key], interval{ipv4Range{first, last}, index})
	}
	unscoped := make(map[int]bool)
	var private [][2]netip.Addr
	for _, group := range groups {
		slices.SortFunc(group, func(a, b interval) int {
			if order := cmp.Compare(a.first, b.first); order != 0 {
				return order
			}
			return cmp.Compare(b.last, a.last)
		})
		next := uint64(firstUnicastIPv4)
		var omittedPublic uint64
		covered := make([]interval, 0, len(group))
		for _, row := range group {
			if uint64(row.last) < next {
				continue
			}
			if uint64(row.first) > next && !nonPublicGap(uint32(next), row.first-1) {
				omittedPublic += uint64(row.first) - next
				// A missing public subnet is a scope boundary, not a host exemption.
				if omittedPublic >= publicSubnetSize {
					break
				}
			}
			covered = append(covered, row)
			next = uint64(row.last) + 1
			if next > lastUnicastIPv4 {
				break
			}
		}
		if next <= lastUnicastIPv4 {
			continue
		}
		selected := make(map[ipv4Range]bool, len(covered))
		for _, row := range covered {
			selected[row.ipv4Range] = true
		}
		for _, row := range group {
			if !selected[row.ipv4Range] && (row.first > firstUnicastIPv4 || row.last < lastUnicastIPv4) {
				continue
			}
			unscoped[row.index] = true
			for _, bounds := range privateRanges {
				first, last := max(row.first, bounds.first), min(row.last, bounds.last)
				if first <= last {
					private = append(private, [2]netip.Addr{ipv4Address(first), ipv4Address(last)})
				}
			}
		}
	}
	if len(unscoped) == 0 {
		return resources, nil
	}
	slices.SortFunc(private, func(a, b [2]netip.Addr) int {
		if first := a[0].Compare(b[0]); first != 0 {
			return first
		}
		return a[1].Compare(b[1])
	})
	scoped := make([]client.IPResource, 0, len(resources)-len(unscoped))
	for i, row := range resources {
		if !unscoped[i] {
			scoped = append(scoped, row)
		}
	}
	return scoped, slices.Compact(private)
}

func isPrivateRange(first, last uint32) bool {
	for _, bounds := range privateRanges {
		if first >= bounds.first && last <= bounds.last {
			return true
		}
	}
	return false
}

func nonPublicGap(first, last uint32) bool {
	return isPrivateRange(first, last) || (ipv4Address(first).IsLoopback() && ipv4Address(last).IsLoopback()) ||
		(ipv4Address(first).IsLinkLocalUnicast() && ipv4Address(last).IsLinkLocalUnicast())
}

func ipv4Address(number uint32) netip.Addr {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], number)
	return netip.AddrFrom4(value)
}
