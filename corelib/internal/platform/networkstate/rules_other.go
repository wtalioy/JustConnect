//go:build !linux

package networkstate

func readPolicyRules() ([]PolicyRule, error) { return nil, nil }
