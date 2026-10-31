package bridge

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/service"
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
	IPs                  []ipResource                    `json:"ip_resources"`
	Domains              map[string][]resourcePermission `json:"domain_resources"`
	DNSRecords           map[string][]string             `json:"dns_records"`
	CampusDNS            string                          `json:"campus_dns"`
	CampusDNSEnabled     bool                            `json:"campus_dns_enabled"`
	UnderlayInterface    string                          `json:"underlay_interface"`
	Listeners            service.ListenerAddresses       `json:"listeners"`
	ActiveTUNAddresses   []string                        `json:"active_tun_addresses,omitempty"`
	OriginalDNSRecords   map[string][]string             `json:"original_dns_records,omitempty"`
	OriginalDNSListeners map[string]string               `json:"original_dns_listeners,omitempty"`
}

type resourcesEnvelope struct {
	SchemaVersion int              `json:"schema_version"`
	Generation    uint64           `json:"generation,string"`
	Resources     resourceSnapshot `json:"resources"`
}

func (s *Session) setResources(resources corelib.Resources) Status {
	s.mu.Lock()
	generation := s.generation
	if !s.running || s.stopping {
		s.mu.Unlock()
		return Cancelled
	}
	s.mu.Unlock()
	snapshot := resourceSnapshot{IPs: []ipResource{}, Domains: map[string][]resourcePermission{}, DNSRecords: map[string][]string{}, CampusDNS: resources.CampusDNS, CampusDNSEnabled: resources.CampusDNSEnabled, UnderlayInterface: resources.UnderlayInterface, Listeners: resources.Listeners}
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
	data, err := json.Marshal(resourcesEnvelope{ABIVersion, generation, snapshot})
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
	if s.protocol == nil {
		return bytes.Clone(s.resources), OK
	}
	// A publication hold ends only after its DNS binding exists; read the hold side first.
	active := s.protocol.ActiveTUNAddresses()
	records := s.protocol.CampusDNSRecords()
	original := s.protocol.OriginalDNSRecords()
	listeners := s.protocol.OriginalDNSListeners()
	if len(records) == 0 && len(original) == 0 && len(active) == 0 && len(listeners) == 0 {
		return bytes.Clone(s.resources), OK
	}
	var snapshot resourcesEnvelope
	if json.Unmarshal(s.resources, &snapshot) != nil {
		return nil, Internal
	}
	snapshot.Resources.ActiveTUNAddresses = active
	snapshot.Resources.OriginalDNSRecords = original
	snapshot.Resources.OriginalDNSListeners = listeners
	for host, addresses := range records {
		for _, address := range addresses {
			if !slices.Contains(snapshot.Resources.DNSRecords[host], address) {
				snapshot.Resources.DNSRecords[host] = append(snapshot.Resources.DNSRecords[host], address)
			}
		}
		slices.Sort(snapshot.Resources.DNSRecords[host])
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, Internal
	}
	if len(data) > MaxOutput {
		return nil, Limit
	}
	return data, OK
}
