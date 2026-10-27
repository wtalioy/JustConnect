//go:build windows

package mihomo

import (
	native "github.com/wtalioy/JustConnect/corelib/internal/mihomo/windows"
	"os"
)

var Processes = native.Read
var validProcess = native.Valid
var ownsTCP = native.OwnsTCP
var dialIPC = native.DialIPC
var openConfiguration = os.Open
