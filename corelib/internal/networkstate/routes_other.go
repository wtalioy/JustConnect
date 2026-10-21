//go:build !windows && !linux && !darwin

package networkstate

func readRoutes([]Interface) ([]Route, error) {
	return nil, ErrUnsupported
}
