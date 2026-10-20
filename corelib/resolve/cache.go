package resolve

import (
	"net"

	"github.com/patrickmn/go-cache"
)

const maxDNSCacheEntries = 4096

func (r *Resolver) getDNSCache(host string) (net.IP, bool) {
	host = normalizeHostname(host)
	if item, found := r.dnsCache.Get(host); found {
		return item.(net.IP), found
	} else {
		return nil, found
	}
}

func (r *Resolver) setDNSCache(host string, ip net.IP) {
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
	r.dnsCache.Set(host, ip, cache.DefaultExpiration)
}
