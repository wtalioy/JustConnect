//go:build darwin && cgo

package macos

/*
#include <stdint.h>
extern int jc_macos_owns_tcp_listener(int pid, unsigned short port, uint32_t ipv4) __attribute__((weak_import));
static int verify_tcp_listener(int pid, unsigned short port, uint32_t ipv4) {
	return jc_macos_owns_tcp_listener ? jc_macos_owns_tcp_listener(pid, port, ipv4) : -1;
}
*/
import "C"

func init() {
	verifyTCPListener = func(pid int, port uint16, ipv4 uint32) int {
		return int(C.verify_tcp_listener(C.int(pid), C.ushort(port), C.uint32_t(ipv4)))
	}
}
