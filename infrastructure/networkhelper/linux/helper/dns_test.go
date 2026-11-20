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

func TestDetectDNSModeAcceptsStubAndRunDirectory(t *testing.T) {
	originalRunDir, originalLookPath := resolvedRunDir, lookPath
	t.Cleanup(func() { resolvedRunDir, lookPath = originalRunDir, originalLookPath })
	lookPath = func(string) (string, error) { return "/usr/bin/resolvectl", nil }

	// The stub nameserver marks an active resolved even when the file is not
	// the runtime symlink.
	dir := t.TempDir()
	stub := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(stub, []byte(resolvedStubLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mode, err := detectDNSModeAt(stub); err != nil || mode != dnsModeResolved {
		t.Fatalf("stub detection produced %q, %v", mode, err)
	}

	// The resolved runtime directory layout also counts, stub or not.
	resolvedRunDir = dir
	runtime := filepath.Join(dir, "stub.conf")
	if err := os.WriteFile(runtime, []byte("nameserver 10.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if mode, err := detectDNSModeAt(runtime); err != nil || mode != dnsModeResolved {
		t.Fatalf("runtime-directory detection produced %q, %v", mode, err)
	}

	// A missing resolvectl makes an active resolved unusable.
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if _, err := detectDNSModeAt(runtime); err == nil || !strings.Contains(err.Error(), "resolvectl") {
		t.Fatalf("missing resolvectl must be reported: %v", err)
	}
}

// The live host detection must agree with itself; the value is informational.
func TestDetectDNSModeLive(t *testing.T) {
	if _, err := detectDNSMode(); err != nil {
		t.Logf("host reports no usable DNS mechanism: %v", err)
	}
}
