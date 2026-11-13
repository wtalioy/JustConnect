package corelib

import (
	"context"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/dial"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
	"github.com/wtalioy/JustConnect/corelib/resolve"
)

// A DNS override identifies an address, but the IP grants still decide which ports can use it.
func proxyExportDomainDNS(ctx context.Context, dialer *dial.Dialer, ips []client.IPResource, overrides map[string]string) client.DomainResources {
	if len(overrides) == 0 {
		return nil
	}
	exported := make(client.DomainResources)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names := make(chan string)
	var workers sync.WaitGroup
	var mu sync.Mutex
	for range min(len(overrides), 8) {
		workers.Go(func() {
			for name := range names {
				resolved, ip, err := dialer.Resolve(ctx, name)
				if err != nil || resolved.Value(resolve.ContextKeyDomainResource) != nil || ip.Equal(dialer.OriginalAuthentication.Address.AsSlice()) {
					continue
				}
				number, ok := ipresource.IPv4Uint32(ip)
				if !ok {
					continue
				}
				var permissions []client.DomainResource
				for _, grant := range ips {
					first, firstOK := ipresource.IPv4Uint32(grant.IPMin)
					last, lastOK := ipresource.IPv4Uint32(grant.IPMax)
					if firstOK && lastOK && first <= number && number <= last {
						permissions = append(permissions, client.DomainResource{Protocol: grant.Protocol, PortMin: grant.PortMin, PortMax: grant.PortMax})
					}
				}
				if len(permissions) != 0 {
					mu.Lock()
					exported[name] = permissions
					mu.Unlock()
				}
			}
		})
	}
send:
	for name := range overrides {
		select {
		case names <- name:
		case <-ctx.Done():
			break send
		}
	}
	close(names)
	workers.Wait()
	return exported
}
