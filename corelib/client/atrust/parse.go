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
					Tun0RTT struct {
						MaxIdleConnNum    int64 `json:"maxIdleConnNum"`
						MaxIdleLingerTime int64 `json:"maxIdleLingerTime"`
						MinIdleConnNum    int64 `json:"minIdleConnNum"`
						Enable            bool  `json:"enable"`
						PreConnNum        int64 `json:"preConnNum"`
					} `json:"tun0rtt"`

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
				if address.Protocol == "tcp" || address.Protocol == "udp" || address.Protocol == "all" {
					// Handle port
					portStr := address.Port
					var portMin, portMax int
					if strings.Contains(portStr, "-") {
						// Handle port range
						ports := strings.Split(portStr, "-")
						if len(ports) != 2 {

							continue
						}
						portMin, err = strconv.Atoi(ports[0])
						if err != nil {

							continue
						}
						portMax, err = strconv.Atoi(ports[1])
						if err != nil {

							continue
						}
					} else {
						// Handle single port
						portMin, err = strconv.Atoi(portStr)
						if err != nil {

							continue
						}
						portMax = portMin // Single port means min and max are the same
					}
					// Keep exactly the usable destination ports authorized by the server range.
					portMin, portMax = max(1, portMin), min(65535, portMax)
					if portMin > portMax {
						continue
					}

					// Handle host
					hostStr := address.Host
					isDomain := false
					// First, try to parse the host as an IP address
					ip := net.ParseIP(hostStr)
					if ip == nil {
						// Try to parse as CIDR notation (e.g. 10.13.0.0/16)
						if _, ipNet, cidrErr := net.ParseCIDR(hostStr); cidrErr == nil {
							ip4 := ipNet.IP.To4()
							if ip4 != nil {
								ipMax4 := make(net.IP, len(ip4))
								for i := range ip4 {
									ipMax4[i] = ip4[i] | ^ipNet.Mask[i]
								}

								c.ipResources = append(c.ipResources, client.IPResource{
									IPMin:           ip4.To16(),
									IPMax:           ipMax4.To16(),
									PortMin:         portMin,
									PortMax:         portMax,
									Protocol:        address.Protocol,
									AppID:           appItem.ID,
									NodeGroupID:     appItem.NodeGroupID,
									EnableTCPPrefL3: appItem.EnableTCPPrefL3,
								})

							} else {

							}
						} else if ipParts := strings.Split(hostStr, "-"); len(ipParts) == 2 {
							ipMin := net.ParseIP(ipParts[0])
							ipMax := net.ParseIP(ipParts[1])
							if ipMin != nil && ipMax != nil {
								// It's a range of IP addresses
								if ipMin.To4() != nil {

									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin:           ipMin,
										IPMax:           ipMax,
										PortMin:         portMin,
										PortMax:         portMax,
										Protocol:        address.Protocol,
										AppID:           appItem.ID,
										NodeGroupID:     appItem.NodeGroupID,
										EnableTCPPrefL3: appItem.EnableTCPPrefL3,
									})

								} else {

								}
							} else {
								isDomain = true
							}
						} else {
							isDomain = true
						}
					} else {
						// It's an IP address
						if ip.To4() != nil {

							c.ipResources = append(c.ipResources, client.IPResource{
								IPMin:           ip,
								IPMax:           ip,
								PortMin:         portMin,
								PortMax:         portMax,
								Protocol:        address.Protocol,
								AppID:           appItem.ID,
								NodeGroupID:     appItem.NodeGroupID,
								EnableTCPPrefL3: appItem.EnableTCPPrefL3,
							})

						} else {

						}
					}

					if isDomain {
						domain := normalizePolicyDomain(hostStr)
						if domain == "" {

							continue
						}
						c.domainResources[domain] = append(c.domainResources[domain], client.DomainResource{
							PortMin:         portMin,
							PortMax:         portMax,
							Protocol:        address.Protocol,
							AppID:           appItem.ID,
							NodeGroupID:     appItem.NodeGroupID,
							EnableTCPPrefL3: appItem.EnableTCPPrefL3,
							AddrPretend:     resourceAddrPretend(appItem.AddrPretend),
						})

					}

					// Handle DNS rules
					if address.IP != nil {
						if !isDomain {

							continue
						}

						for _, ipStr := range address.IP {
							ip := net.ParseIP(ipStr)
							if ip != nil {
								if ip.To4() != nil {

									c.dnsResource[hostStr] = append(c.dnsResource[hostStr], ip)
									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin: ip, IPMax: ip, PortMin: portMin, PortMax: portMax,
										Protocol: address.Protocol, AppID: appItem.ID, NodeGroupID: appItem.NodeGroupID,
										EnableTCPPrefL3: appItem.EnableTCPPrefL3,
									})

								} else {

								}
							} else {

							}
						}
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
