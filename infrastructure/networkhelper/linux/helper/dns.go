//go:build linux

// DNS ownership for the privileged helper. Linux hosts vary widely: the core
// answers queries sent to the TUN peer address, so reaching that address is
// the host's job. Automatic routing requires an active systemd-resolved:
// per-link split DNS via resolvectl (dns + route-only routing domains on the
// TUN interface), withdrawn with `revert`.
//
// A plain /etc/resolv.conf fallback was deliberately removed: prepending the
// campus resolver there captures every query on the host — not just campus
// domains — and a crash can leave that order in place. Hosts without an
// active systemd-resolved are reported as unavailable so the application can
// tell the user automatic mode cannot run before starting a connection.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	dnsModeSkipped  = ""
	dnsModeResolved = "resolved"

	resolvedStubLine = "nameserver 127.0.0.53"
)

// Var so tests can relocate the resolved runtime directory.
var resolvedRunDir = "/run/systemd/resolve"

// Var instead of const so tests can relocate the file.
var resolvConfPath = "/etc/resolv.conf"

// Var so tests can stub the resolver binary lookup.
var lookPath = exec.LookPath

// dnsOwnership records exactly what was mutated so the session can withdraw
// it later, including after a helper restart (the state file keeps it).
// planDNS computes the whole record before applyDNS touches anything, so the
// write-ahead state file always describes a mutation that is either not yet
// made or fully withdrawable.
type dnsOwnership struct {
	Mode    string   `json:"mode"`
	Iface   string   `json:"interface,omitempty"`
	Peer    string   `json:"peer,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// detectDNSMode decides which DNS mechanism this host offers, or fails with a
// user-presentable reason when none is usable.
func detectDNSMode() (string, error) {
	return detectDNSModeAt(resolvConfPath)
}

func detectDNSModeAt(resolvPath string) (string, error) {
	real, err := filepath.EvalSymlinks(resolvPath)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", resolvPath, err)
	}
	active := strings.HasPrefix(real, resolvedRunDir+"/")
	if !active {
		if data, readErr := os.ReadFile(real); readErr == nil {
			active = strings.Contains(string(data), resolvedStubLine)
		}
	}
	if !active {
		return "", fmt.Errorf("%s does not point at an active systemd-resolved; automatic routing has no supported DNS mechanism", resolvPath)
	}
	if _, err := lookPath("resolvectl"); err != nil {
		return "", errors.New("systemd-resolved is active but resolvectl is missing")
	}
	return dnsModeResolved, nil
}

// applyDNS installs campus DNS from a plan produced by planDNS.
func applyDNS(ownership *dnsOwnership) error {
	if ownership.Mode != dnsModeResolved {
		return fmt.Errorf("unsupported DNS mode %q", ownership.Mode)
	}
	if err := runCommand("resolvectl", "default-route", ownership.Iface, "false"); err != nil {
		return fmt.Errorf("exclude the campus resolver from ordinary DNS: %w", err)
	}
	if err := runCommand("resolvectl", "dns", ownership.Iface, ownership.Peer); err != nil {
		return fmt.Errorf("set per-link DNS server: %w", err)
	}
	args := []string{"domain", ownership.Iface}
	for _, domain := range ownership.Domains {
		args = append(args, "~"+domain)
	}
	if err := runCommand("resolvectl", args...); err != nil {
		// Withdraw the half-applied per-link settings.
		_ = runCommand("resolvectl", "revert", ownership.Iface)
		return fmt.Errorf("set per-link routing domains: %w", err)
	}
	return nil
}

// planDNS computes the complete ownership record without mutating anything.
// applyDNS later executes this plan.
func planDNS(mode, iface, peer string, domains []string) (*dnsOwnership, error) {
	if mode != dnsModeResolved {
		return nil, fmt.Errorf("unsupported DNS mode %q", mode)
	}
	return &dnsOwnership{
		Mode:    mode,
		Iface:   iface,
		Peer:    peer,
		Domains: append([]string{}, domains...),
	}, nil
}

// withdrawDNS undoes applyDNS. Best effort: a vanished interface already
// released its per-link settings.
func withdrawDNS(ownership *dnsOwnership) error {
	if ownership == nil || ownership.Mode == dnsModeSkipped {
		return nil
	}
	if ownership.Mode != dnsModeResolved {
		return fmt.Errorf("unsupported DNS mode %q", ownership.Mode)
	}
	if err := runCommand("resolvectl", "revert", ownership.Iface); err != nil {
		if ifaceExists(ownership.Iface) {
			return fmt.Errorf("revert per-link DNS: %w", err)
		}
	}
	return nil
}

func ifaceExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

func runCommand(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(output)))
	}
	return nil
}
