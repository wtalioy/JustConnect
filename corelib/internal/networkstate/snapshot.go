// Package networkstate reads original interfaces and routes without changing them.
package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"runtime"
)

func Read() (model.Snapshot, error) {
	interfaces, err := Interfaces()
	if err != nil {
		return model.Snapshot{}, err
	}
	snapshot := model.Snapshot{OS: runtime.GOOS, Interfaces: interfaces}
	snapshot.Routes, err = readRoutes()
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

// Interfaces reads interface facts without collecting routes or DNS settings.
func Interfaces() ([]model.Interface, error) {
	return readInterfaces()
}
