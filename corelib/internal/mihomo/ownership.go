package mihomo

// Three advertised proxy protocols, each on IPv4 and IPv6.
const MaxListenerProofs = 6

// ListenerProof is a native helper observation, never a controller's claim.
type ListenerProof struct {
	PID      int    `json:"pid,string"`
	Started  uint64 `json:"started,string"`
	Endpoint string `json:"endpoint"`
	Inode    uint64 `json:"inode,string"`
}

type ListenerRequest struct {
	PID       int      `json:"pid,string"`
	Started   uint64   `json:"started,string"`
	Endpoints []string `json:"endpoints"`
}
