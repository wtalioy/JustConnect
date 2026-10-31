package testmihomo

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/dnslistener"
)

// StartBinary runs only an explicitly supplied test runtime, with no TUN or system changes.
func StartBinary(t testing.TB, upstream string, ipc bool) *Fixture {
	t.Helper()
	return StartConfiguredBinary(t, upstream, ipc, nil)
}

func StartConfiguredBinary(t testing.TB, upstream string, ipc bool, overrides map[string]any) *Fixture {
	t.Helper()
	source := os.Getenv("JC_TEST_MIHOMO_BINARY")
	if source == "" {
		t.Skip("set JC_TEST_MIHOMO_BINARY to run the official Mihomo integration")
	}
	directory, err := os.MkdirTemp("", "jcr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(directory, name)
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	reserve := func(network string) string {
		listener, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	dnsTCP, dnsUDP, err := dnslistener.Listen(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := dnsTCP.Addr().String()
	dnsTCP.Close()
	dnsUDP.Close()
	f := &Fixture{DNS: dnsAddress, Facts: Facts{Address: reserve("tcp"), Secret: filepath.Base(directory)}, Configuration: filepath.Join(directory, "config.json")}
	config := map[string]any{
		"external-controller": f.Address, "secret": f.Secret,
		"port": 0, "socks-port": 0, "mixed-port": 0, "allow-lan": false,
		"log-level": "info", "tun": map[string]any{"enable": false},
		"dns": map[string]any{"enable": true, "listen": f.DNS, "ipv6": true,
			"enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16", "fake-ip-filter": []string{},
			"use-hosts": false, "use-system-hosts": false,
			"nameserver": []string{upstream}, "default-nameserver": []string{"127.0.0.1"}},
		"rules": []string{"MATCH,REJECT"},
	}
	for key, value := range overrides {
		config[key] = value
	}
	if tun, ok := config["tun"].(map[string]any); !ok || tun["enable"] != false {
		t.Fatal("owned controller fixture must keep TUN disabled")
	}
	if ipc {
		key := "external-controller-unix"
		f.IPC = ipcName(directory)
		if runtime.GOOS == "windows" {
			key = "external-controller-pipe"
		}
		config[key] = f.IPC
	}
	data, _ = json.Marshal(config)
	if err = os.WriteFile(f.Configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-d", directory, "-f", f.Configuration)
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	f.PID = command.Process.Pid
	t.Cleanup(func() {
		command.Process.Kill()
		command.Wait()
		if t.Failed() {
			t.Logf("owned Mihomo log: %s", log.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", f.Address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("official Mihomo did not start its owned controller")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, key := range []string{"socks-port", "mixed-port"} {
		port, _ := config[key].(int)
		if port == 0 {
			continue
		}
		for {
			connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
			if err == nil {
				connection.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("official Mihomo did not start its owned %s", key)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return f
}
