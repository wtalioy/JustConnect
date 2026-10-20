package hook_func

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// get all services and skip element contains "*"
func ListNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var services []string
	for _, line := range lines[1:] { // Skip the first header line
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "*") {
			services = append(services, line)
		}
	}
	return services, nil
}

func SetDNSServerWithHook(service, dns string) error {
	// networksetup -setdnsservers "service name" DNS_IP
	cmd := exec.Command("networksetup", "-setdnsservers", service, dns)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	RegisterTerminalFunc("CleanDnsServer_"+service, func(ctx context.Context) error {
		delCommand := exec.Command("networksetup", "-setdnsservers", service, "Empty")
		delErr := delCommand.Run()
		if delErr != nil {
			return delErr
		}
		return nil
	})

	return nil
}
