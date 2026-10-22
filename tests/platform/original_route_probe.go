//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wtalioy/JustConnect/corelib/underlay"
)

func run() error {
	if len(os.Args) != 3 || os.Getuid() == 0 || os.Geteuid() == 0 || (os.Args[1] != "capture" && os.Args[1] != "original") {
		return fmt.Errorf("requires mode, interface and an ordinary receiving user")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000") {
		return fmt.Errorf("receiver retained capabilities")
	}
	dialer, err := underlay.New(underlay.Options{InterfaceName: os.Args[2]})
	if err != nil {
		return err
	}
	defer dialer.Close()
	if os.Args[1] != "capture" {
		dialer.ExcludeIP(net.ParseIP("198.18.0.1"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if os.Args[1] == "capture" {
		conn, err := dialer.DialContext(ctx, "udp", "198.18.0.6:54321")
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte("capture-probe"))
		return err
	}
	for _, network := range []string{"tcp", "udp"} {
		conn, err := dialer.DialContext(ctx, network, "198.18.0.6:54321")
		if err != nil {
			return err
		}
		err = conn.SetDeadline(time.Now().Add(time.Second))
		if err == nil {
			_, err = io.WriteString(conn, "bound-original")
		}
		response := make([]byte, len("original-network"))
		if err == nil {
			_, err = io.ReadFull(conn, response)
		}
		local := conn.LocalAddr().String()
		conn.Close()
		if err != nil || string(response) != "original-network" || !strings.HasPrefix(local, "192.0.2.1:") {
			return fmt.Errorf("%s failed to retain original interface: %v", network, err)
		}
	}
	fmt.Println("PASS: ordinary Go underlay TCP/UDP retained original interface beneath a more-specific capture route")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
