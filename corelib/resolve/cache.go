package resolve

import (
	"net"

	"github.com/patrickmn/go-cache"
)

const maxDNSCacheEntries = 4096

type cachedDNSAnswer struct {
	ip     net.IP
	campus bool
}

func (r *Resolver) getDNSCache(host string, campusOnly bool) (net.IP, bool) {
	host = normalizeHostname(host)
	if item, found := r.dnsCache.Get(host); found {
		if answer, ok := item.(cachedDNSAnswer); ok && (!campusOnly || answer.campus) {
			return answer.ip, true
		}
	}
	return nil, false
}

func (r *Resolver) setDNSCache(host string, ip net.IP, campus bool) {
	host = normalizeHostname(host)
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	// No unowned janitor goroutine; discard expired entries when the cache fills.
	if r.dnsCache.ItemCount() >= maxDNSCacheEntries {
		r.dnsCache.DeleteExpired()
		if r.dnsCache.ItemCount() >= maxDNSCacheEntries {
			return
		}
	}
	r.dnsCache.Set(host, cachedDNSAnswer{ip: ip, campus: campus}, cache.DefaultExpiration)
}
