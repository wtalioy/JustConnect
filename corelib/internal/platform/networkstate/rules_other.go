//go:build !linux

package networkstate

import "github.com/wtalioy/JustConnect/corelib/internal/platform/networkstate/model"

func readPolicyRules() ([]model.PolicyRule, error) { return nil, nil }
