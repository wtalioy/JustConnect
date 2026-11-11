package ipresource

import (
	"cmp"
	"encoding/binary"
	"net"
	"slices"

	"github.com/wtalioy/JustConnect/corelib/client"
)

type indexedResource struct {
	resource client.IPResource
	start    uint32
	end      uint32
	maxEnd   uint32
	order    int
	left     *indexedResource
	right    *indexedResource
}

type Index struct {
	root *indexedResource
}

func New(resources []client.IPResource) *Index {
	indexed := make([]indexedResource, 0, len(resources))
	for order, resource := range resources {
		start, startOK := IPv4Uint32(resource.IPMin)
		end, endOK := IPv4Uint32(resource.IPMax)
		if !startOK || !endOK || start > end {
			continue
		}
		indexed = append(indexed, indexedResource{resource: resource, start: start, end: end, order: order})
	}
	slices.SortFunc(indexed, func(a, b indexedResource) int { return cmp.Compare(a.start, b.start) })
	return &Index{root: build(indexed)}
}

func build(resources []indexedResource) *indexedResource {
	if len(resources) == 0 {
		return nil
	}
	middle := len(resources) / 2
	resource := &resources[middle]
	resource.left = build(resources[:middle])
	resource.right = build(resources[middle+1:])
	resource.maxEnd = resource.end
	if resource.left != nil {
		resource.maxEnd = max(resource.maxEnd, resource.left.maxEnd)
	}
	if resource.right != nil {
		resource.maxEnd = max(resource.maxEnd, resource.right.maxEnd)
	}
	return resource
}

func (i *Index) Match(destination net.IP, protocol string, port int) (client.IPResource, bool) {
	return i.match(destination, protocol, port, false, nil)
}

func (i *Index) MatchWhere(destination net.IP, protocol string, port int, accept func(client.IPResource) bool) (client.IPResource, bool) {
	return i.match(destination, protocol, port, false, accept)
}

func (i *Index) MatchLastWhere(destination net.IP, protocol string, port int, accept func(client.IPResource) bool) (client.IPResource, bool) {
	return i.match(destination, protocol, port, true, accept)
}

func (i *Index) match(destination net.IP, protocol string, port int, preferLast bool, accept func(client.IPResource) bool) (client.IPResource, bool) {
	ip, ok := IPv4Uint32(destination)
	if !ok || i == nil || i.root == nil {
		return client.IPResource{}, false
	}
	var best *indexedResource
	i.root.match(ip, protocol, port, preferLast, accept, &best)
	if best == nil {
		return client.IPResource{}, false
	}
	return best.resource, true
}

func (resource *indexedResource) match(ip uint32, protocol string, port int, preferLast bool, accept func(client.IPResource) bool, best **indexedResource) {
	if resource.maxEnd < ip {
		return
	}
	if resource.left != nil && resource.left.maxEnd >= ip {
		resource.left.match(ip, protocol, port, preferLast, accept, best)
	}
	if resource.start > ip {
		return
	}
	if ip <= resource.end &&
		(resource.resource.Protocol == protocol || resource.resource.Protocol == "all") &&
		(protocol == "icmp" || resource.resource.PortMin <= port && port <= resource.resource.PortMax) &&
		(accept == nil || accept(resource.resource)) &&
		(*best == nil || (!preferLast && resource.order < (*best).order) || (preferLast && resource.order > (*best).order)) {
		*best = resource
	}
	if resource.right != nil && resource.right.maxEnd >= ip {
		resource.right.match(ip, protocol, port, preferLast, accept, best)
	}
}

func IPv4Uint32(ip net.IP) (uint32, bool) {
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}
