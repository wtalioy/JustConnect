//go:build darwin

package testmihomo

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// StartPrivilegedBinary is CI setup only; the Go caller remains an ordinary user.
func StartPrivilegedBinary(t testing.TB, upstream string) *Fixture {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "macOS" || os.Getenv("JC_TEST_MIHOMO_BINARY") == "" {
		t.Skip("root-owned controller setup requires the disposable macOS runtime check")
	}
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() {
		t.Fatal("controller consumer must remain an ordinary user")
	}
	directory, err := os.MkdirTemp("", "jcm-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.sock")
	command := exec.Command("/usr/bin/sudo", "-n", "--", "/usr/bin/env", "GITHUB_ACTIONS="+os.Getenv("GITHUB_ACTIONS"), "python3", "-u", "-c", rootController,
		os.Getenv("JC_TEST_MIHOMO_BINARY"), path, upstream)
	control, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	command.Stderr = &log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		control.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("owned root controller cleanup: %v; %s", err, log.String())
			} else if t.Failed() {
				t.Log(log.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("owned root controller exceeded its EOF cleanup budget")
		}
	})
	var facts struct {
		PID           int
		Configuration string
	}
	ready := make(chan error, 1)
	go func() { ready <- json.NewDecoder(reader).Decode(&facts) }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owned root controller readiness deadline")
	}
	return &Fixture{Facts: Facts{IPC: path}, PID: facts.PID, Configuration: facts.Configuration}
}

const rootController = `
import json, os, pathlib, select, subprocess, sys, tempfile, time
assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
binary, endpoint, upstream = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='jcm-private-') as directory:
    root = pathlib.Path(directory)
    config = root / 'config.json'
    config.write_text(json.dumps({
        'external-controller-unix': endpoint, 'port': 0, 'socks-port': 0, 'mixed-port': 0,
        'log-level': 'info', 'tun': {'enable': False},
        'dns': {'enable': True, 'use-hosts': False, 'use-system-hosts': False,
                'nameserver': [upstream], 'default-nameserver': ['127.0.0.1']},
        'rules': ['MATCH,REJECT']}), encoding='utf-8')
    config.chmod(0o600)
    with (root / 'process.log').open('w+') as log:
        process = subprocess.Popen([binary, '-d', directory, '-f', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 8
            while not pathlib.Path(endpoint).exists():
                assert process.poll() is None, 'root-owned Mihomo exited before readiness'
                assert time.monotonic() < deadline, 'root-owned Mihomo readiness deadline'
                if select.select([sys.stdin], [], [], 0.02)[0] and not sys.stdin.buffer.read(1):
                    raise RuntimeError('caller closed during root controller startup')
            print(json.dumps({'PID': process.pid, 'Configuration': str(config)}), flush=True)
            sys.stdin.buffer.read()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            log.seek(0)
            sys.stderr.write(log.read())
`
