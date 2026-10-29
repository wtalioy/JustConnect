// Package networkstate reads original interfaces, routes and policy rules without changing them.
package networkstate

import (
	"errors"
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"runtime"
)

var ErrUnsupported = errors.New("unsupported route snapshot platform")

func Supported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

func Read() (model.Snapshot, error) {
	interfaces, err := Interfaces()
	if err != nil {
		return model.Snapshot{}, err
	}
	snapshot := model.Snapshot{OS: runtime.GOOS, Interfaces: interfaces}
	snapshot.Routes, err = readRoutes(snapshot.Interfaces)
	if err != nil {
		return model.Snapshot{}, err
	}
	snapshot.PolicyRules, err = readPolicyRules()
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

// Interfaces reads interface facts without collecting routes or DNS settings.
func Interfaces() ([]model.Interface, error) {
	if !Supported() {
		return nil, ErrUnsupported
	}
	return readInterfaces()
}
