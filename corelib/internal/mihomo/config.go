package mihomo

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"gopkg.in/yaml.v3"
)

const maxConfigurationBytes = 4 << 20

var ErrUnavailable = errors.New("local_controller_unavailable")
var ErrAmbiguous = errors.New("local_controller_ambiguous")

type endpoint struct {
	process                          model.Process
	network, address, scheme, secret string
	serverName                       string
}
type configuration struct {
	Controller string `yaml:"external-controller"`
	TLS        string `yaml:"external-controller-tls"`
	Unix       string `yaml:"external-controller-unix"`
	Pipe       string `yaml:"external-controller-pipe"`
	Secret     string `yaml:"secret"`
}

func arguments(args []string) map[string]string {
	values := make(map[string]string)
	for i := 1; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") || args[i] == "--" {
			break
		}
		key, value, equals := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		switch key {
		case "d", "f", "config", "ext-ctl", "ext-ctl-tls", "ext-ctl-unix", "ext-ctl-pipe", "secret":
		default:
			continue
		}
		if !equals {
			if i+1 >= len(args) {
				continue
			}
			i++
			value = args[i]
		}
		values[key] = value
	}
	return values
}

func absolute(path, directory string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if directory == "" {
		return "", ErrUnavailable
	}
	return filepath.Join(directory, path), nil
}

func endpoints(p model.Process) ([]endpoint, error) {
	args := arguments(p.Args)
	home := args["d"]
	if home == "" && p.Home != "" {
		home = filepath.Join(p.Home, ".config", "mihomo")
	}
	if home != "" {
		var err error
		home, err = absolute(home, p.Directory)
		if err != nil {
			return nil, err
		}
	}
	// Native IPC does not use the TCP controller's secret (Mihomo hub/route/server.go).
	if runtime.GOOS == "windows" && args["ext-ctl-pipe"] != "" {
		return ipcEndpoint(p, "pipe", args["ext-ctl-pipe"], "")
	}
	if args["ext-ctl-unix"] != "" {
		return ipcEndpoint(p, "unix", args["ext-ctl-unix"], home)
	}
	var c configuration
	var data []byte
	var err error
	if args["config"] != "" {
		data, err = base64.StdEncoding.DecodeString(args["config"])
	} else {
		file := args["f"]
		if file == "-" {
			return nil, ErrUnavailable
		}
		if file == "" {
			if home != "" {
				file = filepath.Join(home, "config.yaml")
			}
		}
		if file != "" {
			file, err = absolute(file, p.Directory)
			if err == nil {
				var reader *os.File
				reader, err = openConfiguration(file)
				if err == nil {
					info, statErr := reader.Stat()
					if statErr != nil || !info.Mode().IsRegular() {
						reader.Close()
						return nil, ErrUnavailable
					}
					data, err = io.ReadAll(io.LimitReader(reader, maxConfigurationBytes+1))
					reader.Close()
				}
			}
		}
	}
	if err == nil && len(data) != 0 {
		if len(data) > maxConfigurationBytes || yaml.Unmarshal(data, &c) != nil {
			return nil, ErrUnavailable
		}
	} else if args["ext-ctl"] == "" && args["ext-ctl-tls"] == "" {
		return nil, ErrUnavailable
	}
	for key, target := range map[string]*string{"ext-ctl": &c.Controller, "ext-ctl-tls": &c.TLS, "secret": &c.Secret} {
		if args[key] != "" {
			*target = args[key]
		}
	}
	if runtime.GOOS == "windows" && c.Pipe != "" {
		return ipcEndpoint(p, "pipe", c.Pipe, "")
	}
	if c.Unix != "" {
		return ipcEndpoint(p, "unix", c.Unix, home)
	}
	var result []endpoint
	for _, item := range []struct{ address, scheme string }{{c.Controller, "http"}, {c.TLS, "https"}} {
		if item.address == "" {
			continue
		}
		host, port, err := net.SplitHostPort(item.address)
		if err != nil {
			return nil, ErrUnavailable
		}
		serverName := host
		hosts := []string{host}
		switch strings.ToLower(host) {
		case "", "0.0.0.0", "localhost":
			hosts = []string{"127.0.0.1", "::1"}
		case "::":
			hosts = []string{"::1", "127.0.0.1"}
		}
		for _, host := range hosts {
			address, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
			if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
				return nil, ErrUnavailable
			}
			result = append(result, endpoint{process: p, network: "tcp", address: address.String(), scheme: item.scheme, secret: c.Secret, serverName: serverName})
		}
	}
	if len(result) == 0 {
		return nil, ErrUnavailable
	}
	return result, nil
}

func ipcEndpoint(p model.Process, kind, address, home string) ([]endpoint, error) {
	if strings.ContainsAny(address, "\x00\r\n") || len(address) > 4096 {
		return nil, ErrUnavailable
	}
	if kind == "pipe" {
		if !strings.HasPrefix(strings.ToLower(address), `\\.\pipe\`) || strings.Contains(address[len(`\\.\pipe\`):], `\`) {
			return nil, ErrUnavailable
		}
	} else {
		var err error
		address, err = absolute(address, home)
		if err != nil {
			return nil, err
		}
	}
	return []endpoint{{process: p, network: kind, address: address, scheme: "http"}}, nil
}
