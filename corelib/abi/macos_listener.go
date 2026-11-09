//go:build darwin && cgo

package main

/*
#include "macos_listener.h"
*/
import "C"

import (
	"unsafe"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/macos"
)

//export jc_macos_set_tcp_listener_verifier
func jc_macos_set_tcp_listener_verifier(verifier C.jc_tcp_listener_verifier) {
	macos.SetTCPListenerVerifier(unsafe.Pointer(verifier))
}
