package bridge

import (
	"bytes"
	"encoding/json"

	"github.com/wtalioy/JustConnect/corelib"
)

type resourcePermission struct {
	Protocol string `json:"protocol"`
	PortMin  int    `json:"port_min"`
	PortMax  int    `json:"port_max"`
}

type ipResource struct {
	IPMin string `json:"ip_min"`
	IPMax string `json:"ip_max"`
	resourcePermission
}

type resourceSnapshot struct {
	IPs              []ipResource                    `json:"ip_resources"`
	Domains          map[string][]resourcePermission `json:"domain_resources"`
	DNSRecords       map[string][]string             `json:"dns_records"`
	CampusDNS        string                          `json:"campus_dns"`
	CampusDNSEnabled bool                            `json:"campus_dns_enabled"`
}

func (s *Session) setResources(resources corelib.Resources) Status {
	s.mu.Lock()
	generation := s.generation
	if !s.running || s.stopping {
		s.mu.Unlock()
		return Cancelled
	}
	s.mu.Unlock()
	snapshot := resourceSnapshot{IPs: []ipResource{}, Domains: map[string][]resourcePermission{}, DNSRecords: map[string][]string{}, CampusDNS: resources.CampusDNS, CampusDNSEnabled: resources.CampusDNSEnabled}
	for _, row := range resources.IPs {
		snapshot.IPs = append(snapshot.IPs, ipResource{row.IPMin.String(), row.IPMax.String(), resourcePermission{row.Protocol, row.PortMin, row.PortMax}})
	}
	for domain, rows := range resources.Domains {
		permissions := []resourcePermission{}
		for _, row := range rows {
			permissions = append(permissions, resourcePermission{row.Protocol, row.PortMin, row.PortMax})
		}
		snapshot.Domains[domain] = permissions
	}
	for domain, addresses := range resources.DNSRecords {
		values := []string{}
		for _, address := range addresses {
			values = append(values, address.String())
		}
		snapshot.DNSRecords[domain] = values
	}
	data, err := json.Marshal(struct {
		SchemaVersion int              `json:"schema_version"`
		Generation    uint64           `json:"generation,string"`
		Resources     resourceSnapshot `json:"resources"`
	}{ABIVersion, generation, snapshot})
	status := OK
	if err != nil {
		status = Internal
	} else if len(data) > MaxOutput {
		status = Limit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping || s.generation != generation {
		return Cancelled
	}
	s.resourcesStatus = status
	s.resources = nil
	if status == OK {
		s.resources = data
	}
	return status
}

func (e *Engine) Resources(handle, generation uint64) ([]byte, Status) {
	if generation == 0 {
		return nil, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return nil, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, InvalidHandle
	}
	if !s.running || s.stopping || s.generation != generation {
		return nil, StaleRequest
	}
	if !s.connectOperation {
		return nil, Unsupported
	}
	if s.resourcesStatus != OK {
		return nil, s.resourcesStatus
	}
	return bytes.Clone(s.resources), OK
}
