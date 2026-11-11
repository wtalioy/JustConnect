package resolve

import (
	"strings"

	"github.com/wtalioy/JustConnect/corelib/client"
)

type domainResourceEntry struct {
	domain    string
	resources []client.DomainResource
}

type domainResourceIndex map[string]*domainResourceEntry

func newDomainResourceIndex(resources client.DomainResources) domainResourceIndex {
	index := make(domainResourceIndex, len(resources))
	for domain, domainResources := range resources {
		normalized := normalizeHostname(domain)
		if strings.HasPrefix(normalized, "*.") {
			normalized = normalized[1:]
		}
		if normalized == "" {
			continue
		}
		entry := index[normalized]
		if entry == nil {
			entry = &domainResourceEntry{domain: domain}
			index[normalized] = entry
		}
		entry.resources = append(entry.resources, domainResources...)
	}
	return index
}

func (i domainResourceIndex) Match(host string) (string, []client.DomainResource, bool) {
	if len(i) == 0 {
		return "", nil, false
	}
	var local [4]*domainResourceEntry
	matches := local[:0]
	total := 0
	for pos := 0; pos < len(host); {
		if entry := i[host[pos:]]; entry != nil {
			matches = append(matches, entry)
			total += len(entry.resources)
		}
		// Include both sides of each label separator for ordinary and wildcard rules.
		if host[pos] == '.' {
			pos++
			continue
		}
		dot := strings.IndexByte(host[pos:], '.')
		if dot < 0 {
			break
		}
		pos += dot
	}
	if len(matches) == 0 {
		return "", nil, false
	}
	if len(matches) == 1 {
		return matches[0].domain, matches[0].resources, true
	}
	resources := make([]client.DomainResource, 0, total)
	for _, entry := range matches {
		resources = append(resources, entry.resources...)
	}
	return matches[0].domain, resources, true
}
