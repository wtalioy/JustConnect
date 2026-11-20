//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func withStateRoot(t *testing.T) {
	t.Helper()
	stateRoot = filepath.Join(t.TempDir(), "justconnect-state")
}

func TestStateRoundTrip(t *testing.T) {
	withStateRoot(t)
	if err := prepareStateDir(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	info, err := os.Stat(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state dir is not private: %v", info.Mode())
	}

	state := &ownedState{
		Version:  stateVersion,
		UID:      1000,
		PID:      4242,
		Device:   &deviceInfo{Name: "tun9", Index: 9, MTU: 1400, Address: "10.22.4.1", Peer: "10.22.4.2"},
		Prefixes: []string{"10.50.0.0/16"},
		Dynamic:  []string{"10.50.1.5/32"},
		DNS:      &dnsOwnership{Mode: dnsModeResolved, Iface: "tun9", Peer: "10.22.4.2"},
	}
	if err := saveState(state); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := loadState(1000)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil || loaded.Device == nil || loaded.Device.Name != "tun9" {
		t.Fatalf("unexpected record %+v", loaded)
	}
	if len(loaded.Prefixes) != 1 || loaded.Prefixes[0] != "10.50.0.0/16" {
		t.Fatalf("prefixes lost: %+v", loaded)
	}
	if loaded.DNS == nil || loaded.DNS.Iface != "tun9" || loaded.DNS.Peer != "10.22.4.2" {
		t.Fatalf("dns record lost: %+v", loaded)
	}
	if err := clearState(1000); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if state, err := loadState(1000); err != nil || state != nil {
		t.Fatalf("clear left %v (%v)", state, err)
	}
}

func TestLoadStateMissingAndCorrupt(t *testing.T) {
	withStateRoot(t)
	if err := prepareStateDir(); err != nil {
		t.Fatal(err)
	}
	if state, err := loadState(1000); err != nil || state != nil {
		t.Fatalf("empty store returned %v (%v)", state, err)
	}
	if err := os.WriteFile(statePath(1001), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(1001); err == nil {
		t.Fatal("corrupt record accepted")
	}
}
