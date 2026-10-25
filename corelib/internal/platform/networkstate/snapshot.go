// Package networkstate reads original interfaces, routes and policy rules without changing them.
package networkstate

import (
	"errors"
	"github.com/wtalioy/JustConnect/corelib/internal/platform/networkstate/model"
	"net"
	"net/netip"
	"runtime"
	"slices"
)

var ErrUnsupported = errors.New("unsupported route snapshot platform")

func Supported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

func Read() (model.Snapshot, error) {
	if !Supported() {
		return model.Snapshot{}, ErrUnsupported
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return model.Snapshot{}, err
	}
	snapshot := model.Snapshot{OS: runtime.GOOS, Interfaces: []model.Interface{}}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return model.Snapshot{}, err
		}
		item := model.Interface{Index: iface.Index, Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return model.Snapshot{}, err
			}
			item.Addresses = append(item.Addresses, prefix.String())
		}
		slices.Sort(item.Addresses)
		snapshot.Interfaces = append(snapshot.Interfaces, item)
	}
	snapshot.Routes, err = readRoutes(snapshot.Interfaces)
	if err != nil {
		return model.Snapshot{}, err
	}
	snapshot.PolicyRules, err = readPolicyRules()
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}
