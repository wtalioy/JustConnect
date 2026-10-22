package bridge

import "github.com/wtalioy/JustConnect/corelib/policy"

type ProtectionConfig struct {
	Protected []string `json:"protected"`
	Campus    []string `json:"campus"`
}

type PolicyUpdate struct {
	SchemaVersion int      `json:"schema_version"`
	Generation    uint64   `json:"generation,string"`
	Revision      uint64   `json:"revision,string"`
	Protected     []string `json:"protected"`
	Campus        []string `json:"campus"`
}

// ProtectionPolicy returns an immutable snapshot for one new connection.
func (s *Session) ProtectionPolicy() *policy.ProtectionPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy
}

func (e *Engine) UpdatePolicy(handle uint64, input []byte) (uint64, Status) {
	var update PolicyUpdate
	if !decode(input, &update) || update.SchemaVersion != ABIVersion || update.Generation == 0 || update.Revision == 0 || update.Protected == nil || update.Campus == nil {
		return 0, InvalidArgument
	}
	policy, err := policy.NewProtectionPolicy(update.Protected, update.Campus)
	if err != nil {
		return 0, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return 0, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return 0, InvalidHandle
	}
	if !s.running || s.stopping || update.Generation != s.generation || update.Revision <= s.policyRevision {
		return 0, StaleRequest
	}
	if !s.connectOperation {
		return 0, Unsupported
	}
	s.policy, s.policyRevision = &policy, update.Revision
	return s.generation, OK
}
