package address

import "net/netip"

// ValidIPv4Pair matches the helper's distinct unicast point-to-point address contract.
func ValidIPv4Pair(local, peer netip.Addr) bool {
	valid := func(address netip.Addr) bool {
		return address.Is4() && address.As4()[0] > 0 && address.As4()[0] < 224 && address.As4()[0] != 127
	}
	return valid(local) && valid(peer) && local != peer
}
