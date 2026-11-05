package ipresource

import (
	"net"
	"slices"

	"github.com/wtalioy/JustConnect/corelib/client"
)

// CaptureRanges treats a full IPv4 grant as authorization, not as a public
// default route. Keep RFC 1918 ranges for campus IP access and preserve
// narrower grants. Named campus traffic can still use the full authorization.
func CaptureRanges(resources []client.IPResource) ([]client.IPResource, bool) {
	first := slices.IndexFunc(resources, coversIPv4)
	if first < 0 {
		return resources, false
	}
	result := slices.Clone(resources[:first])
	for _, entry := range resources[first:] {
		if !coversIPv4(entry) {
			result = append(result, entry)
			continue
		}
		for _, bounds := range privateIPv4 {
			entry.IPMin, entry.IPMax = bounds[0], bounds[1]
			result = append(result, entry)
		}
	}
	return result, true
}

func coversIPv4(resource client.IPResource) bool {
	start, startOK := IPv4Uint32(resource.IPMin)
	end, endOK := IPv4Uint32(resource.IPMax)
	// Include gateways that advertise the full usable unicast range instead of 0/0.
	return startOK && endOK && start <= 0x01000000 && end >= 0xdfffffff
}

var privateIPv4 = [][2]net.IP{
	{net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255)},
	{net.IPv4(172, 16, 0, 0), net.IPv4(172, 31, 255, 255)},
	{net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 255, 255)},
}
