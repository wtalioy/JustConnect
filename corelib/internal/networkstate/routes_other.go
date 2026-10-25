//go:build !windows && !linux && !darwin

package networkstate

import "github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"

func readRoutes([]model.Interface) ([]model.Route, error) {
	return nil, ErrUnsupported
}
