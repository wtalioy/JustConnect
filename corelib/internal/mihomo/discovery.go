package mihomo

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

// ControllerInfo contains only verified, non-secret facts suitable for display.
type ControllerInfo struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func (e endpoint) identifier() string {
	if e.network == "tcp" {
		return e.scheme + "://" + e.address
	}
	return e.network + "://" + e.address
}

func controllerEndpoint(address string) (endpoint, error) {
	if address == "" || !utf8.ValidString(address) || strings.TrimSpace(address) != address || strings.ContainsAny(address, "\x00\r\n") || len(address) > 4096 {
		return endpoint{}, ErrUnavailable
	}
	for _, kind := range []string{"unix", "pipe"} {
		if path, found := strings.CutPrefix(address, kind+"://"); found {
			if (kind == "pipe") != (runtime.GOOS == "windows") || kind == "unix" && !filepath.IsAbs(path) {
				return endpoint{}, ErrUnavailable
			}
			list, err := ipcEndpoint(model.Process{}, kind, path, "")
			if err != nil {
				return endpoint{}, err
			}
			return list[0], nil
		}
	}
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return endpoint{}, ErrUnavailable
	}
	target, err := netip.ParseAddrPort(parsed.Host)
	if err != nil || !target.Addr().IsLoopback() || target.Port() == 0 || target.Addr().Zone() != "" {
		return endpoint{}, ErrUnavailable
	}
	return endpoint{network: "tcp", scheme: parsed.Scheme, address: target.String(), serverName: target.Addr().String()}, nil
}

// ValidateControllerAddress never discovers a process or sends a request.
func ValidateControllerAddress(address string) bool {
	if address == "" {
		return true
	}
	_, err := controllerEndpoint(address)
	return err == nil
}

func Discover(ctx context.Context, address string) (*Client, error) {
	controller, _, err := scanControllers(ctx, address)
	return controller, err
}

func Candidates(ctx context.Context) ([]ControllerInfo, error) {
	controller, candidates, err := scanControllers(ctx, "")
	if controller != nil {
		controller.Close()
	}
	if errors.Is(err, ErrAmbiguous) {
		err = nil
	}
	return candidates, err
}

func scanControllers(ctx context.Context, address string) (*Client, []ControllerInfo, error) {
	var requested endpoint
	var err error
	if address != "" {
		requested, err = controllerEndpoint(address)
		if err != nil {
			return nil, nil, err
		}
	}
	processes, err := Processes(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, ErrUnavailable
	}
	candidates := []ControllerInfo{}
	var selected *Client
	for _, process := range processes {
		if ctx.Err() != nil {
			break
		}
		list, endpointErr := endpoints(process)
		if address != "" {
			matches := []endpoint{}
			for _, e := range list {
				if e.identifier() == requested.identifier() {
					matches = append(matches, e)
				}
			}
			if len(matches) == 0 {
				manual := requested
				manual.process = process
				matches = append(matches, manual)
			}
			list = matches
		} else if endpointErr != nil {
			continue
		}
		candidate, err := inspectEndpoints(ctx, list)
		if err != nil {
			continue
		}
		name := "Mihomo"
		if len(process.Args) != 0 {
			name = filepath.Base(process.Args[0])
		}
		candidates = append(candidates, ControllerInfo{PID: process.PID, Name: name, Endpoint: candidate.endpoint.identifier()})
		if selected == nil {
			selected = candidate
		} else {
			candidate.Close()
		}
	}
	if ctx.Err() != nil || len(candidates) > 1 {
		if selected != nil {
			selected.Close()
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, candidates, ErrAmbiguous
	}
	// A saved selection does not require Clash to remain running.
	if selected == nil && len(processes) != 0 {
		return nil, candidates, ErrUnavailable
	}
	return selected, candidates, nil
}
