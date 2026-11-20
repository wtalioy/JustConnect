//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Automatic routing has exactly one supported DNS mechanism: an active
// systemd-resolved. Anything else must fail detectability before a connection
// starts, so the application can explain the requirement.
func TestDetectDNSModeRequiresActiveResolved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := detectDNSModeAt(path)
	if err == nil || !strings.Contains(err.Error(), "systemd-resolved") {
		t.Fatalf("a plain resolv.conf must be rejected: %v", err)
	}
	if _, err := detectDNSModeAt(filepath.Join(dir, "missing.conf")); err == nil {
		t.Fatal("a missing resolv.conf must be reported as unusable")
	}
}

func TestDetectDNSModeRequiresExclusiveStub(t *testing.T) {
	originalLookPath := lookPath
	t.Cleanup(func() { lookPath = originalLookPath })
	lookPath = func(string) (string, error) { return "/usr/bin/resolvectl", nil }

	dir := t.TempDir()
	stub := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(stub, []byte("nameserver\t127.0.0.53 # local stub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mode, err := detectDNSModeAt(stub); err != nil || mode != dnsModeResolved {
		t.Fatalf("stub detection produced %q, %v", mode, err)
	}

	uplink := filepath.Join(dir, "uplink.conf")
	for _, contents := range []string{
		"nameserver 10.0.0.1\n", "# nameserver 127.0.0.53\n", "nameserver 127.0.0.530\n",
		"nameserver 127.0.0.53\nnameserver 10.0.0.1\n",
	} {
		if err := os.WriteFile(uplink, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := detectDNSModeAt(uplink); err == nil {
			t.Fatalf("configuration bypassing the DNS stub was accepted: %q", contents)
		}
	}

	// A missing resolvectl makes an active resolved unusable.
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if _, err := detectDNSModeAt(stub); err == nil || !strings.Contains(err.Error(), "resolvectl") {
		t.Fatalf("missing resolvectl must be reported: %v", err)
	}
}
