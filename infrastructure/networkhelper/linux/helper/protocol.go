// Package main implements the privileged Linux network helper. It is spawned
// through pkexec (one polkit authorization per application launch), connects
// back to the unprivileged JustConnect process over an abstract unix socket,
// and owns every mutating network operation: TUN creation, addresses, routes
// and DNS. The JustConnect process only borrows the resulting raw IPv4 file
// descriptor; address, route and DNS ownership stays here until the session
// ends (explicit restore, socket EOF, or a signal), matching the core contract
// in corelib/internal/tundevice/linux.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// helperProtocol is the control wire version; it must match the Qt client.
const helperProtocol = 1

// maxRequestBytes bounds one control frame. Replies carry at most the device
// envelope, so the same bound applies in both directions.
const maxRequestBytes = 65536

var ownerPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Control operations. probe/restore/cleanup/close carry only the envelope.
const (
	opProbe   = "probe"
	opApply   = "apply"
	opExtend  = "extend"
	opRoutes  = "routes"
	opRestore = "restore"
	opCleanup = "cleanup"
	opClose   = "close"
)

// Reply statuses mirror the Qt PlatformOperationResult statuses.
const (
	statusOK               = "ok"
	statusFailed           = "failed"
	statusPermissionDenied = "permission_denied"
	statusUnsupported      = "unsupported"
)

type request struct {
	Version   int      `json:"version"`
	Operation string   `json:"operation"`
	Owner     string   `json:"owner"`
	RequestID string   `json:"request_id"`
	Address   string   `json:"address,omitempty"`
	Peer      string   `json:"peer,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	Prefixes  []string `json:"prefixes,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Domains   []string `json:"dns_domains,omitempty"`
}

// applyConfiguration carries the validated fields of one apply request.
type applyConfiguration struct {
	Address  string
	Peer     string
	MTU      int
	Prefixes []string
	Domains  []string
}

var errMalformed = errors.New("malformed helper request")

// allowedFields enforces the exact field set per operation so both sides fail
// loudly on a protocol drift instead of guessing.
var allowedFields = map[string][]string{
	opProbe:   {},
	opApply:   {"address", "peer", "mtu", "prefixes", "dns_domains"},
	opExtend:  {"addresses"},
	opRoutes:  {"prefixes"},
	opRestore: {},
	opCleanup: {},
	opClose:   {},
}

func parseRequest(payload []byte) (*request, error) {
	if len(payload) == 0 || len(payload) > maxRequestBytes {
		return nil, errMalformed
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	decoded := &request{}
	if err := json.Unmarshal(payload, decoded); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	if decoded.Version != helperProtocol {
		return nil, fmt.Errorf("unsupported helper protocol %d", decoded.Version)
	}
	fields, known := allowedFields[decoded.Operation]
	if !known {
		return nil, fmt.Errorf("%w: unknown operation %q", errMalformed, decoded.Operation)
	}
	for name := range raw {
		switch name {
		case "version", "operation", "owner", "request_id":
			continue
		}
		permitted := false
		for _, field := range fields {
			if field == name {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, fmt.Errorf("%w: unexpected field %q for %q", errMalformed, name, decoded.Operation)
		}
	}
	if !ownerPattern.MatchString(decoded.Owner) || !ownerPattern.MatchString(decoded.RequestID) {
		return nil, fmt.Errorf("%w: owner and request_id must be canonical UUIDs", errMalformed)
	}
	if _, err := decoded.configuration(); err != nil {
		return nil, err
	}
	return decoded, nil
}

// configuration validates and extracts the operation-specific payload; it
// returns nil for the envelope-only operations.
func (r *request) configuration() (*applyConfiguration, error) {
	switch r.Operation {
	case opApply:
		config := &applyConfiguration{Address: r.Address, Peer: r.Peer, MTU: r.MTU, Prefixes: append([]string{}, r.Prefixes...), Domains: append([]string{}, r.Domains...)}
		if config.MTU <= 0 || len(config.Prefixes) == 0 || config.Address == "" || config.Peer == "" || config.Address == config.Peer {
			return nil, fmt.Errorf("%w: apply needs a distinct address pair, a positive mtu and at least one prefix", errMalformed)
		}
		return config, nil
	case opExtend:
		if len(r.Addresses) == 0 {
			return nil, fmt.Errorf("%w: extend needs at least one address", errMalformed)
		}
		return nil, nil
	case opRoutes:
		if len(r.Prefixes) == 0 {
			return nil, fmt.Errorf("%w: routes needs at least one prefix", errMalformed)
		}
		return nil, nil
	default:
		if len(r.Prefixes) != 0 || len(r.Addresses) != 0 || len(r.Domains) != 0 || r.Address != "" || r.Peer != "" || r.MTU != 0 {
			return nil, fmt.Errorf("%w: %q carries no payload fields", errMalformed, r.Operation)
		}
		return nil, nil
	}
}

type response struct {
	Version   int         `json:"version"`
	Operation string      `json:"operation"`
	Owner     string      `json:"owner"`
	RequestID string      `json:"request_id"`
	Status    string      `json:"status"`
	Detail    string      `json:"detail,omitempty"`
	Device    *deviceInfo `json:"device,omitempty"`
	// DNSMode reports the DNS mechanism the helper detected (probe) or used
	// (apply): "resolved", "file", or "" when DNS was not needed.
	DNSMode string `json:"dns_mode,omitempty"`
}

type deviceInfo struct {
	Name    string `json:"name"`
	Index   int    `json:"index"`
	MTU     int    `json:"mtu"`
	Address string `json:"address"`
	Peer    string `json:"peer"`
}

func (r *request) reply(status, detail string, device *deviceInfo) *response {
	return &response{Version: helperProtocol, Operation: r.Operation, Owner: r.Owner,
		RequestID: r.RequestID, Status: status, Detail: detail, Device: device}
}
