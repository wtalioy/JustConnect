//go:build linux

package mihomo

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/mihomo/linux"
	"golang.org/x/sys/unix"
	"os"
)

var Processes = native.Read
var validProcess = native.Valid
var ownsTCP = native.OwnsTCP
var dialIPC = native.DialIPC
var openConfiguration = func(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0) }
