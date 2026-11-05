package resolve

import (
	"net"
	"time"
)

const maxDNSCacheEntries = 4096

type cachedDNSAnswer struct {
	ip      net.IP
	campus  bool
	expires int64
}

func (r *Resolver) getDNSCache(host string, campusOnly bool) (net.IP, bool) {
	host = normalizeHostname(host)
	r.cacheMu.RLock()
	answer, found := r.dnsCache[host]
	r.cacheMu.RUnlock()
	if !found || (campusOnly && !answer.campus) || (answer.expires > 0 && time.Now().UnixNano() >= answer.expires) {
		return nil, false
	}
	return answer.ip, true
}

func (r *Resolver) setDNSCache(host string, ip net.IP, campus bool) {
	host = normalizeHostname(host)
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now().UnixNano()
	if _, found := r.dnsCache[host]; !found && len(r.dnsCache) >= maxDNSCacheEntries {
		if r.nextDNSExpiry == 0 || now < r.nextDNSExpiry {
			return
		}
		r.nextDNSExpiry = 0
		for name, answer := range r.dnsCache {
			if answer.expires > 0 && now >= answer.expires {
				delete(r.dnsCache, name)
			} else if answer.expires > 0 && (r.nextDNSExpiry == 0 || answer.expires < r.nextDNSExpiry) {
				r.nextDNSExpiry = answer.expires
			}
		}
		if len(r.dnsCache) >= maxDNSCacheEntries {
			return
		}
	}
	var expires int64
	if r.dnsCacheTTL > 0 {
		expires = now + int64(r.dnsCacheTTL)
		if r.nextDNSExpiry == 0 || expires < r.nextDNSExpiry {
			r.nextDNSExpiry = expires
		}
	}
	if r.dnsCache == nil {
		r.dnsCache = make(map[string]cachedDNSAnswer)
	}
	r.dnsCache[host] = cachedDNSAnswer{ip: ip, campus: campus, expires: expires}
}
