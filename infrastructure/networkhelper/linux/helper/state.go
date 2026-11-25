//go:build linux

// Session ownership persistence. The helper keeps a write-ahead record under
// /run/justconnect so that a SIGKILLed helper leaves just enough information
// for the next instance to withdraw the DNS and device mutations that outlive
// the process. /run is tmpfs, so a reboot clears everything. A per-uid flock
// serializes concurrent helpers the way the Windows mutex does.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	stateVersion  = 1
	stateFileMode = 0600
	stateDirMode  = 0700
)

// stateRoot is the staging directory root; a var so tests can relocate it.
var stateRoot = "/run/justconnect"

// ownedState is the write-ahead record for one application identity.
type ownedState struct {
	Version  int           `json:"version"`
	UID      int           `json:"uid"`
	PID      int           `json:"pid"`
	Device   *deviceInfo   `json:"device,omitempty"`
	Prefixes []string      `json:"prefixes,omitempty"`
	Dynamic  []string      `json:"dynamic,omitempty"`
	DNS      *dnsOwnership `json:"dns,omitempty"`
}

func statePath(uid int) string {
	return filepath.Join(stateRoot, fmt.Sprintf("owner-%d.json", uid))
}

func lockPath(uid int) string {
	return filepath.Join(stateRoot, fmt.Sprintf("owner-%d.lock", uid))
}

// prepareStateDir guarantees a private root-owned staging directory.
func prepareStateDir() error {
	if err := os.MkdirAll(stateRoot, stateDirMode); err != nil {
		return fmt.Errorf("create %s: %w", stateRoot, err)
	}
	info, err := os.Stat(stateRoot)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not a private root-owned directory", stateRoot)
	}
	return nil
}

// acquireOwnership takes the per-uid flock for this helper's lifetime.
func acquireOwnership(uid int) (*os.File, error) {
	f, err := os.OpenFile(lockPath(uid), os.O_CREATE|os.O_RDWR, stateFileMode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", lockPath(uid), err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another JustConnect network helper already owns uid %d: %w", uid, err)
	}
	return f, nil
}

// loadState returns nil when no record exists.
func loadState(uid int) (*ownedState, error) {
	data, err := os.ReadFile(statePath(uid))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", statePath(uid), err)
	}
	state := &ownedState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("parse %s: %w", statePath(uid), err)
	}
	if state.Version != stateVersion {
		return nil, fmt.Errorf("%s carries unsupported version %d", statePath(uid), state.Version)
	}
	return state, nil
}

func saveState(state *ownedState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > maxRequestBytes {
		return errors.New("ownership record exceeds the frame bound")
	}
	tmp := statePath(state.UID) + ".tmp"
	if err := os.WriteFile(tmp, data, stateFileMode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, statePath(state.UID)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("publish %s: %w", statePath(state.UID), err)
	}
	return nil
}

func clearState(uid int) error {
	err := os.Remove(statePath(uid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
