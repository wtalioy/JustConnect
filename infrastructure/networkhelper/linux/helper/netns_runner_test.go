//go:build linux

package main

import (
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// disposableTUN owns one real TUN device for the netns runner.
type disposableTUN struct {
	dev *tunDevice
}

func openRunnerTUN(t *testing.T, label string) *disposableTUN {
	t.Helper()
	dev, err := openTUN()
	if err != nil {
		t.Fatalf("open %s TUN: %v", label, err)
	}
	local := netip.MustParseAddr("10.22.4.1")
	peer := netip.MustParseAddr("10.22.4.2")
	if label == "conflicting" {
		local, peer = netip.MustParseAddr("10.22.8.1"), netip.MustParseAddr("10.22.8.2")
	}
	if err := dev.configure(local, peer, 1400); err != nil {
		dev.close()
		t.Fatalf("configure %s TUN: %v", label, err)
	}
	return &disposableTUN{dev: dev}
}

func (r *disposableTUN) close() { r.dev.close() }

// routesFor lists the routes the RIB holds for one interface index.
func routesFor(t *testing.T, index int) []routeTarget {
	t.Helper()
	rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		t.Fatalf("dump routes: %v", err)
	}
	targets, err := dumpRoutes(rib, index)
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	return targets
}

func containsPrefix(targets []routeTarget, prefix netip.Prefix) bool {
	for _, target := range targets {
		if target.hasDst && netip.PrefixFrom(target.dst, int(target.dstLen)) == prefix {
			return true
		}
	}
	return false
}

// TestNetlinkExclusiveRouteRunner exercises the real netlink route path in a
// private root network namespace — the disposable-runner scenario: a route
// another tool owns must survive connect and disconnect, while the helper's
// own leftover row from a crashed instance must be accepted again.
func TestNetlinkExclusiveRouteRunner(t *testing.T) {
	if os.Getenv("JC_LINUX_HELPER_NETNS") != "1" {
		t.Skip("conflicting-route scenarios run in a disposable root network namespace (JC_LINUX_HELPER_NETNS=1)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the netns runner requires root inside the private namespace")
	}

	campus := netip.MustParsePrefix("10.50.0.0/16")
	owned := openRunnerTUN(t, "owned")
	defer owned.close()
	foreign := openRunnerTUN(t, "conflicting")
	defer foreign.close()

	// Another tool owns the destination first.
	if err := foreign.dev.nl.addRoute(foreign.dev.index, campus); err != nil {
		t.Fatalf("install the conflicting foreign route: %v", err)
	}

	// The exclusive add must refuse the collision instead of replacing the
	// foreign row.
	err := owned.dev.nl.addRoute(owned.dev.index, campus)
	if err == nil || !strings.Contains(err.Error(), "another owner") {
		t.Fatalf("a foreign route was replaced or silently accepted: %v", err)
	}
	if !containsPrefix(routesFor(t, foreign.dev.index), campus) {
		t.Fatal("the conflicting route did not survive the refused connect")
	}

	// Withdraw the foreign route exactly as its owner would, then connect.
	if err := foreign.dev.nl.delRoute(foreign.dev.index, campus); err != nil {
		t.Fatalf("foreign owner withdraw: %v", err)
	}
	if err := owned.dev.nl.addRoute(owned.dev.index, campus); err != nil {
		t.Fatalf("clean exclusive add: %v", err)
	}

	// A crashed helper reconnects onto its own leftover row.
	if err := owned.dev.nl.addRoute(owned.dev.index, campus); err != nil {
		t.Fatalf("the helper's own leftover route was not accepted: %v", err)
	}

	foreignRoute := netip.MustParsePrefix("10.80.0.0/16")
	if err := foreign.dev.nl.addRoute(foreign.dev.index, foreignRoute); err != nil {
		t.Fatalf("install the unrelated route: %v", err)
	}
	record := &ownedState{Device: &deviceInfo{
		Name: owned.dev.name, Index: owned.dev.index,
		Address: owned.dev.local.String(), Peer: owned.dev.peer.String(),
	}}
	if err := withdrawRecordedState(record); err != nil {
		t.Fatalf("recover the recorded device: %v", err)
	}
	if targets := routesFor(t, owned.dev.index); len(targets) != 0 {
		t.Fatalf("the owned device still carries routes after recovery: %+v", targets)
	}
	if !containsPrefix(routesFor(t, foreign.dev.index), foreignRoute) {
		t.Fatal("recovery removed the unrelated route")
	}
}

// TestNetlinkExclusiveAddFlagsRunner pins the wire behavior the unit tests
// assert: a duplicate add never creates a second row — the kernel refuses it
// with EEXIST and the ownership check accepts the helper's own leftover.
func TestNetlinkExclusiveAddFlagsRunner(t *testing.T) {
	if os.Getenv("JC_LINUX_HELPER_NETNS") != "1" {
		t.Skip("conflicting-route scenarios run in a disposable root network namespace (JC_LINUX_HELPER_NETNS=1)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the netns runner requires root inside the private namespace")
	}
	dev := openRunnerTUN(t, "owned")
	defer dev.close()
	prefix := netip.MustParsePrefix("10.60.0.0/16")
	if err := dev.dev.nl.addRoute(dev.dev.index, prefix); err != nil {
		t.Fatalf("first add: %v", err)
	}
	// The kernel refuses the exclusive duplicate with EEXIST; the ownership
	// verification accepts the helper's own row without touching it.
	if err := dev.dev.nl.addRoute(dev.dev.index, prefix); err != nil {
		t.Fatalf("the helper's own leftover row was not accepted: %v", err)
	}
	rows := 0
	for _, target := range routesFor(t, dev.dev.index) {
		if target.hasDst && netip.PrefixFrom(target.dst, int(target.dstLen)) == prefix {
			rows++
		}
	}
	if rows != 1 {
		t.Fatalf("the duplicate add left %d rows for %s, expected exactly one", rows, prefix)
	}
}
