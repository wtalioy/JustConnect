//go:build linux || darwin

package testmihomo

import (
	"net"
	"path/filepath"
)

func ipcName(directory string) string                { return filepath.Join(directory, "api.sock") }
func listenIPC(address string) (net.Listener, error) { return net.Listen("unix", address) }
