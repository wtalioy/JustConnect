// Package networkstate reads original interfaces, routes and policy rules without changing them.
package networkstate

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
)

var ErrUnsupported = errors.New("unsupported route snapshot platform")

func Supported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

type Interface struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Up          bool     `json:"up"`
	Loopback    bool     `json:"loopback"`
	Addresses   []string `json:"addresses"`
}

type NextHop struct {
	InterfaceIndex int    `json:"interface_index"`
	Gateway        string `json:"gateway,omitempty"`
	Weight         int    `json:"weight,omitempty"`
	Flags          int    `json:"flags,omitempty"`
}

type Route struct {
	Destination    string    `json:"destination"`
	InterfaceIndex int       `json:"interface_index"`
	Gateway        string    `json:"gateway,omitempty"`
	Source         string    `json:"source,omitempty"`
	Table          int       `json:"table,omitempty"`
	Metric         int       `json:"metric,omitempty"`
	Protocol       int       `json:"protocol,omitempty"`
	Kind           int       `json:"kind,omitempty"`
	Flags          int       `json:"flags,omitempty"`
	NextHops       []NextHop `json:"next_hops,omitempty"`
}

type Snapshot struct {
	OS          string       `json:"os"`
	Interfaces  []Interface  `json:"interfaces"`
	Routes      []Route      `json:"routes"`
	PolicyRules []PolicyRule `json:"policy_rules"`
}

// Attributes retain native Linux selectors, including ones this version does not interpret.
type RuleAttribute struct {
	Type  uint16 `json:"type"`
	Value string `json:"value_hex"`
}

type PolicyRule struct {
	Family      int             `json:"family"`
	Priority    uint32          `json:"priority"`
	Table       uint32          `json:"table"`
	Action      uint8           `json:"action"`
	Flags       uint32          `json:"flags"`
	TOS         uint8           `json:"tos"`
	Source      string          `json:"source,omitempty"`
	Destination string          `json:"destination,omitempty"`
	Attributes  []RuleAttribute `json:"attributes"`
}

func Read() (Snapshot, error) {
	if !Supported() {
		return Snapshot{}, ErrUnsupported
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{OS: runtime.GOOS, Interfaces: []Interface{}}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return Snapshot{}, err
		}
		item := Interface{Index: iface.Index, Name: iface.Name, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return Snapshot{}, err
			}
			item.Addresses = append(item.Addresses, prefix.String())
		}
		slices.Sort(item.Addresses)
		snapshot.Interfaces = append(snapshot.Interfaces, item)
	}
	snapshot.Routes, err = readRoutes(snapshot.Interfaces)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.PolicyRules, err = readPolicyRules()
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}
