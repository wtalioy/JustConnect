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
	for entry := range i.matchingEntries(host) {
		matches = append(matches, entry)
		total += len(entry.resources)
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

func (i domainResourceIndex) Contains(host string) bool {
	for range i.matchingEntries(host) {
		return true
	}
	return false
}

func (i domainResourceIndex) matchingEntries(host string) func(func(*domainResourceEntry) bool) {
	return func(yield func(*domainResourceEntry) bool) {
		if len(i) == 0 {
			return
		}
		for host != "" {
			if entry := i[host]; entry != nil && !yield(entry) {
				return
			}
			// Include both sides of each label separator for ordinary and wildcard rules.
			if host[0] == '.' {
				host = host[1:]
			} else if dot := strings.IndexByte(host, '.'); dot >= 0 {
				host = host[dot:]
			} else {
				return
			}
		}
	}
}
