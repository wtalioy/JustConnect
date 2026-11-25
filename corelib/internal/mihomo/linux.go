//go:build linux

package mihomo

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/mihomo/linux"
	"os"
)

var Processes = native.Read
var validProcess = native.Valid
var ownsTCP = native.OwnsTCP
var filterTCPListeners = native.FilterTCPListeners
var dialIPC = native.DialIPC
var openConfiguration = os.Open
