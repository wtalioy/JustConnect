//go:build darwin && cgo

package macos

/*
#include <stdint.h>
static int verify_tcp_listener(void *verifier, int pid, uint16_t port, uint32_t ipv4) {
	return ((int (*)(int, uint16_t, uint32_t))verifier)(pid, port, ipv4);
}
*/
import "C"

import (
	"sync/atomic"
	"unsafe"
)

var tcpListenerVerifier atomic.Pointer[byte]

func SetTCPListenerVerifier(verifier unsafe.Pointer) {
	tcpListenerVerifier.Store((*byte)(verifier))
}

func init() {
	verifyTCPListener = func(pid int, port uint16, ipv4 uint32) int {
		verifier := tcpListenerVerifier.Load()
		if verifier == nil {
			return -1
		}
		return int(C.verify_tcp_listener(unsafe.Pointer(verifier), C.int(pid), C.uint16_t(port), C.uint32_t(ipv4)))
	}
}
