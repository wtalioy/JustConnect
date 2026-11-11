// Package model contains the native facts used to identify a local controller.
package model

import (
	"net/netip"
	"path/filepath"
	"strings"
)

type Process struct {
	PID             int
	Started         uint64
	Args            []string
	Directory, Home string
	NetworkAdmin    bool
	// IPC contains observed native listener paths; the connector still verifies the peer PID.
	IPC []string
}

func Recognized(name string) bool {
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(name)), ".exe") {
	case "mihomo", "verge-mihomo", "clash-meta", "clash":
		return true
	}
	return false
}

func ListenerMatches(address, target netip.Addr) bool {
	address, target = address.Unmap(), target.Unmap()
	return address.Is4() == target.Is4() && (address.IsUnspecified() || address == target)
}
