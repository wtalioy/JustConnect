package atrust

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
)

type ClientResource struct {
	Data struct {
		AppList struct {
			Data struct {
				AppInfo []struct {
					Apps []resourceApp
				}

				Config struct {
					NodeGroupConf struct {
						MajorNodeGroup struct {
							ID string
						}
						NodeGroupList []struct {
							AddressInfo []struct {
								Address string
								Type    string
							}
							ID string
						}
					}
				}
			}
		}

		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					DNSOption struct {
						FirstDNS  string
						SecondDNS string
					}

					DNSOptionV2 struct {
						FirstDNS  string
						SecondDNS string
					}
				}
			}
		}
	}
}

type resourceApp struct {
	ID              string
	NodeGroupID     string
	AccessModel     string
	EnableTCPPrefL3 bool
	AddrPretend     any `json:"addrPretend"`
	AddressList     []resourceAddress
}

type resourceAddress struct {
	Protocol string
	Port     string
	Host     string
	IP       []string
}

func resourceAddrPretend(value any) bool {
	if value, ok := value.(bool); ok {
		return value
	}
	return true
}

const defaultNodePort = 441

func (c *Client) parseResource(resource []byte) error {

	var clientResource ClientResource
	err := json.Unmarshal(resource, &clientResource)
	if err != nil {
		return err
	}

	c.ipResources = make([]client.IPResource, 0)
	c.domainResources = make(client.DomainResources)
	c.dnsResource = make(map[string][]net.IP)

	for _, app := range clientResource.Data.AppList.Data.AppInfo {
		for _, appItem := range app.Apps {
			if appItem.AccessModel != "L3VPN" {
				continue
			}
			for _, address := range appItem.AddressList {
				if address.Protocol != "tcp" && address.Protocol != "udp" && address.Protocol != "all" {
					continue
				}
				first, last, ranged := strings.Cut(address.Port, "-")
				portMin, err := strconv.Atoi(first)
				if err != nil {
					continue
				}
				portMax := portMin
				if ranged {
					portMax, err = strconv.Atoi(last)
					if err != nil {
						continue
					}
				}
				// Keep exactly the usable destination ports authorized by the server range.
				portMin, portMax = max(1, portMin), min(65535, portMax)
				if portMin > portMax {
					continue
				}
				resource := client.IPResource{
					PortMin: portMin, PortMax: portMax, Protocol: address.Protocol,
					AppID: appItem.ID, NodeGroupID: appItem.NodeGroupID, EnableTCPPrefL3: appItem.EnableTCPPrefL3,
				}
				host := address.Host
				isDomain := false
				if ip := net.ParseIP(host); ip != nil {
					if ip.To4() != nil {
						resource.IPMin, resource.IPMax = ip, ip
					}
				} else if _, subnet, err := net.ParseCIDR(host); err == nil {
					if ip := subnet.IP.To4(); ip != nil {
						last := make(net.IP, len(ip))
						for i := range ip {
							last[i] = ip[i] | ^subnet.Mask[i]
						}
						resource.IPMin, resource.IPMax = ip.To16(), last.To16()
					}
				} else if first, last, ranged := strings.Cut(host, "-"); ranged {
					minimum, maximum := net.ParseIP(first), net.ParseIP(last)
					if minimum != nil && maximum != nil {
						if minimum.To4() != nil {
							resource.IPMin, resource.IPMax = minimum, maximum
						}
					} else {
						isDomain = true
					}
				} else {
					isDomain = true
				}
				if resource.IPMin != nil {
					c.ipResources = append(c.ipResources, resource)
				}
				if !isDomain {
					continue
				}
				domain := normalizePolicyDomain(host)
				if domain == "" {
					continue
				}
				c.domainResources[domain] = append(c.domainResources[domain], client.DomainResource{
					PortMin: portMin, PortMax: portMax, Protocol: address.Protocol,
					AppID: appItem.ID, NodeGroupID: appItem.NodeGroupID, EnableTCPPrefL3: appItem.EnableTCPPrefL3,
					AddrPretend: resourceAddrPretend(appItem.AddrPretend),
				})
				for _, address := range address.IP {
					if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
						c.dnsResource[host] = append(c.dnsResource[host], ip)
						resource.IPMin, resource.IPMax = ip, ip
						c.ipResources = append(c.ipResources, resource)
					}
				}
			}
		}
	}

	dnsOption := clientResource.Data.SDPPolicy.Data.ClientOption.DNSOption
	if dnsOption.FirstDNS == "" {
		dnsOption = clientResource.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	}
	c.dnsServers = c.dnsServers[:0]
	for _, server := range []string{dnsOption.FirstDNS, dnsOption.SecondDNS} {
		if server != "" {
			c.dnsServers = append(c.dnsServers, server)
		}
	}
	if len(c.dnsServers) > 0 {
		c.dnsServer = c.dnsServers[0]

	} else {
		c.dnsServer = ""

	}
	c.MajorNodeGroup = clientResource.Data.AppList.Data.Config.NodeGroupConf.MajorNodeGroup.ID
	c.NodeGroups = make(map[string]NodeGroup)
	for _, nodeGroup := range clientResource.Data.AppList.Data.Config.NodeGroupConf.NodeGroupList {
		addresses := NodeGroup{}
		for _, addressInfo := range nodeGroup.AddressInfo {
			address := addressInfo.Address
			if address == "{{sdpcHost}}" {
				address = c.serverAddress
			}
			if net.ParseIP(address) != nil || !strings.Contains(address, ":") {
				address = net.JoinHostPort(address, strconv.Itoa(defaultNodePort))
			}
			switch strings.ToLower(addressInfo.Type) {
			case "wan":
				addresses.WAN = append(addresses.WAN, address)
			case "lan":
				addresses.LAN = append(addresses.LAN, address)
			default:

			}

		}
		c.NodeGroups[nodeGroup.ID] = addresses

	}

	c.resourceIndex = ipresource.New(c.ipResources)

	return nil
}

func normalizePolicyDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if strings.HasPrefix(domain, "*.") {
		return domain[1:]
	}
	if strings.Contains(domain, "*") {
		return ""
	}
	return domain
}
