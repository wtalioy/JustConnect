//go:build !windows

package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net"
	"net/netip"
	"slices"
)

func readInterfaces() ([]model.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []model.Interface{}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		item := model.Interface{Index: iface.Index, Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, err
			}
			item.Addresses = append(item.Addresses, prefix.String())
		}
		slices.Sort(item.Addresses)
		result = append(result, item)
	}
	return result, nil
}
