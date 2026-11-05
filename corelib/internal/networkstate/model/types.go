// Package model defines the shared native network snapshot contract.
package model

type Interface struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Up          bool     `json:"up"`
	Loopback    bool     `json:"loopback"`
	Addresses   []string `json:"addresses"`
}

type Route struct {
	Destination    string `json:"destination"`
	InterfaceIndex int    `json:"interface_index"`
	Gateway        string `json:"gateway,omitempty"`
	Metric         int    `json:"metric,omitempty"`
	Protocol       int    `json:"protocol,omitempty"`
	Flags          int    `json:"flags,omitempty"`
	Cloned         bool   `json:"cloned,omitempty"`
}

type Snapshot struct {
	OS          string       `json:"os"`
	Interfaces  []Interface  `json:"interfaces"`
	Routes      []Route      `json:"routes"`
	ProxyTunnel *ProxyTunnel `json:"proxy_tunnel,omitempty"`
}

type ProxyTunnel struct {
	InterfaceIndex int    `json:"interface_index"`
	Name           string `json:"name"`
}
