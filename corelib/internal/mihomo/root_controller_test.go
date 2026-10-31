//go:build darwin

package mihomo

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestRootControllerUsesObservedIPCWithoutPrivateConfiguration(t *testing.T) {
	fixture := testmihomo.StartPrivilegedBinary(t, originalControllerDNS(t))
	if _, err := os.ReadFile(fixture.Configuration); !errors.Is(err, os.ErrPermission) {
		t.Fatal("root configuration was not private", err)
	}
	process := ownedProcess(t, fixture.PID)
	if !slices.Contains(process.IPC, fixture.IPC) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		data, err := exec.CommandContext(ctx, "/usr/sbin/netstat", "-anv", "-f", "unix").Output()
		t.Logf("owned socket inventory read: %v", err)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, fixture.IPC) {
				t.Log(line)
			}
		}
		t.Fatalf("root listener missing from PID-owned inventory: pid=%d args_visible=%t", fixture.PID, len(process.Args) != 0)
	}
	client, err := Inspect(t.Context(), process)
	if err != nil {
		t.Fatal("ordinary caller could not inspect the root-owned controller", err)
	}
	defer client.Close()
	answer, err := client.Query(t.Context(), dns.Question{Name: "root-controller.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil || len(answer.Answer) != 1 {
		t.Fatal("root-owned controller real DNS response", err)
	}
	address, ok := answer.Answer[0].(*dns.A)
	if !ok || !address.A.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatal("root-owned controller changed the original DNS result")
	}
	proxy, err := client.Proxy(t.Context())
	if err != nil {
		t.Fatal("ordinary caller could not verify the root-owned data listener", err)
	}
	tcp, udp := proxyEchoTargets(t, "127.0.0.1")
	probe := func(network, target string) error {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		conn, err := proxy.DialContext(ctx, network, target)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("owned")); err != nil {
			return err
		}
		var reply [5]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if string(reply[:]) != "owned" {
			return errors.New("root-owned proxy changed the payload")
		}
		return nil
	}
	fixture.WaitReady(t, func() error { return probe("tcp", tcp) })
	for network, target := range map[string]string{"tcp": tcp, "udp": udp} {
		if err := probe(network, target); err != nil {
			t.Fatalf("ordinary %s data through root-owned Mihomo: %v", network, err)
		}
	}
}
