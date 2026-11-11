#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*jc_tcp_listener_verifier)(int pid, uint16_t port, uint32_t ipv4);
void jc_macos_set_tcp_listener_verifier(jc_tcp_listener_verifier verifier);

#ifdef __cplusplus
}
#endif
