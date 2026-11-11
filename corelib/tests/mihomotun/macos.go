//go:build darwin

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

func ensureOrdinary() error {
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() {
		return fmt.Errorf("control consumer must have an ordinary uid")
	}
	return nil
}

func routeInterface(ctx context.Context, ip netip.Addr) (string, error) {
	output, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "-inet", ip.String()).Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, _ := strings.Cut(line, ":")
		if strings.TrimSpace(key) == "interface" && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("native route omitted its interface")
}
