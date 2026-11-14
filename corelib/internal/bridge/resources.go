package bridge

import (
	"encoding/json"
	"maps"
	"net/netip"
	"slices"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/client"
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
	IPs                           []ipResource                    `json:"ip_resources"`
	PrivateIPRanges               [][2]netip.Addr                 `json:"private_ip_ranges,omitempty"`
	Domains                       map[string][]resourcePermission `json:"domain_resources"`
	DomainDNSPermissions          map[string][]resourcePermission `json:"domain_dns_permissions,omitempty"`
	DNSRecords                    map[string][]string             `json:"dns_records"`
	CampusDNS                     string                          `json:"campus_dns"`
	CampusDNSEnabled              bool                            `json:"campus_dns_enabled"`
	DomainDNSNames                []string                        `json:"domain_dns_names,omitempty"`
	UnderlayInterface             string                          `json:"underlay_interface"`
	OriginalAuthenticationAddress string                          `json:"original_authentication_address,omitempty"`
	Listeners                     service.ListenerAddresses       `json:"listeners"`
	ActiveTUNAddresses            []string                        `json:"active_tun_addresses,omitempty"`
	OriginalDNSRecords            map[string][]string             `json:"original_dns_records,omitempty"`
	OriginalDNSListeners          map[string]string               `json:"original_dns_listeners,omitempty"`
}

type resourcesEnvelope struct {
	SchemaVersion int              `json:"schema_version"`
	Generation    uint64           `json:"generation,string"`
	Resources     resourceSnapshot `json:"resources"`
}

type resourceActivity struct {
	active    []string
	campus    map[string][]string
	original  map[string][]string
	listeners map[string]string
}

func (a resourceActivity) equal(b resourceActivity) bool {
	return slices.Equal(a.active, b.active) &&
		maps.EqualFunc(a.campus, b.campus, slices.Equal[[]string]) &&
		maps.EqualFunc(a.original, b.original, slices.Equal[[]string]) &&
		maps.Equal(a.listeners, b.listeners)
}

type publishedResources struct {
	// Rules are immutable. Only the last encoded view is retained.
	base     resourcesEnvelope
	activity resourceActivity
	data     []byte
}

func encodeResources(snapshot resourcesEnvelope) ([]byte, Status) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, Internal
	}
	if len(data) > MaxOutput {
		return nil, Limit
	}
	return data, OK
}

func copyPermissions(destination map[string][]resourcePermission, source client.DomainResources) {
	for domain, rows := range source {
		permissions := make([]resourcePermission, len(rows))
		for i, row := range rows {
			permissions[i] = resourcePermission{row.Protocol, row.PortMin, row.PortMax}
		}
		destination[domain] = permissions
	}
}

func (s *Session) setResources(resources corelib.Resources) Status {
	s.mu.Lock()
	generation := s.generation
	if !s.running || s.stopping {
		s.mu.Unlock()
		return Cancelled
	}
	s.mu.Unlock()
	snapshot := resourceSnapshot{
		IPs:               make([]ipResource, len(resources.IPs)),
		PrivateIPRanges:   slices.Clone(resources.PrivateIPRanges),
		Domains:           make(map[string][]resourcePermission, len(resources.Domains)),
		DNSRecords:        make(map[string][]string, len(resources.DNSRecords)),
		CampusDNS:         resources.CampusDNS,
		CampusDNSEnabled:  resources.CampusDNSEnabled,
		DomainDNSNames:    slices.Clone(resources.DomainDNSNames),
		UnderlayInterface: resources.UnderlayInterface,
		Listeners:         resources.Listeners,
	}
	if resources.OriginalAuthenticationAddress.IsValid() {
		snapshot.OriginalAuthenticationAddress = resources.OriginalAuthenticationAddress.String()
	}
	for i, row := range resources.IPs {
		snapshot.IPs[i] = ipResource{row.IPMin.String(), row.IPMax.String(), resourcePermission{row.Protocol, row.PortMin, row.PortMax}}
	}
	copyPermissions(snapshot.Domains, resources.Domains)
	if len(resources.DomainDNSPermissions) != 0 {
		snapshot.DomainDNSPermissions = make(map[string][]resourcePermission, len(resources.DomainDNSPermissions))
		copyPermissions(snapshot.DomainDNSPermissions, resources.DomainDNSPermissions)
	}
	for domain, addresses := range resources.DNSRecords {
		values := make([]string, len(addresses))
		for i, address := range addresses {
			values[i] = address.String()
		}
		snapshot.DNSRecords[domain] = values
	}
	base := resourcesEnvelope{ABIVersion, generation, snapshot}
	data, status := encodeResources(base)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping || s.generation != generation {
		return Cancelled
	}
	s.resourcesStatus = status
	s.resources = nil
	if status == OK {
		s.resources = &publishedResources{base: base, data: data}
	}
	return status
}

// CopyResources reports the required size without touching a short destination.
func (e *Engine) CopyResources(handle, generation uint64, dst []byte) (int, Status) {
	if generation == 0 {
		return 0, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return 0, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return 0, InvalidHandle
	}
	if !s.running || s.stopping || s.generation != generation {
		return 0, StaleRequest
	}
	if !s.resourceOperation {
		return 0, Unsupported
	}
	if s.resourcesStatus != OK {
		return 0, s.resourcesStatus
	}
	var activity resourceActivity
	if s.captureOperation && s.protocol != nil {
		// A publication hold ends only after its DNS binding exists; read the hold side first.
		activity = resourceActivity{
			active:    s.protocol.ActiveTUNAddresses(),
			campus:    s.protocol.CampusDNSRecords(),
			original:  s.protocol.OriginalDNSRecords(),
			listeners: s.protocol.OriginalDNSListeners(),
		}
	}
	data, status := s.resources.snapshot(activity)
	if status != OK {
		return 0, status
	}
	return copySnapshot(dst, data)
}

func copySnapshot(dst, data []byte) (int, Status) {
	if len(dst) < len(data) {
		return len(data), BufferTooSmall
	}
	return copy(dst, data), OK
}

func (r *publishedResources) snapshot(activity resourceActivity) ([]byte, Status) {
	if r.activity.equal(activity) {
		return r.data, OK
	}
	view := r.base
	view.Resources.ActiveTUNAddresses = activity.active
	view.Resources.OriginalDNSRecords = activity.original
	view.Resources.OriginalDNSListeners = activity.listeners
	if len(activity.campus) != 0 {
		view.Resources.DNSRecords = maps.Clone(view.Resources.DNSRecords)
		for host, addresses := range activity.campus {
			merged := slices.Clone(view.Resources.DNSRecords[host])
			for _, address := range addresses {
				if !slices.Contains(merged, address) {
					merged = append(merged, address)
				}
			}
			slices.Sort(merged)
			view.Resources.DNSRecords[host] = merged
		}
	}
	data, status := encodeResources(view)
	if status != OK {
		return nil, status
	}
	r.data, r.activity = data, activity
	return data, OK
}
