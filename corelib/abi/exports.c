#define JC_BUILDING
#include "justconnect.h"
#include "_cgo_export.h"

/* Keep the public C const contract separate from cgo's generated pointer types. */
uint32_t jc_abi_version(void) { return jc_go_abi_version(); }
int32_t jc_build_info(uint32_t abi, uint8_t *out, uint32_t cap, uint32_t *len) {
    return jc_go_build_info(abi, out, cap, len);
}
int32_t jc_network_snapshot(uint32_t abi, uint8_t *out, uint32_t cap, uint32_t *len) {
    return jc_go_network_snapshot(abi, out, cap, len);
}
int32_t jc_config_validate(uint32_t abi, const uint8_t *in, uint32_t len) {
    return jc_go_config_validate(abi, (uint8_t *)in, len);
}
int32_t jc_session_create(uint32_t abi, uint64_t *handle) {
    return jc_go_session_create(abi, handle);
}
int32_t jc_session_start(uint64_t h, const uint8_t *in, uint32_t len, uint64_t *generation) {
    return jc_go_session_start(h, (uint8_t *)in, len, generation);
}
int32_t jc_session_read(uint64_t h, uint32_t wait, uint8_t *out, uint32_t cap, uint32_t *len) {
    return jc_go_session_read(h, wait, out, cap, len);
}
int32_t jc_session_respond(uint64_t h, const uint8_t *in, uint32_t len) {
    return jc_go_session_respond(h, (uint8_t *)in, len);
}
int32_t jc_session_update_policy(uint64_t h, const uint8_t *in, uint32_t len, uint64_t *generation) {
    return jc_go_session_update_policy(h, (uint8_t *)in, len, generation);
}
int32_t jc_session_resources(uint64_t h, uint64_t generation, uint8_t *out, uint32_t cap, uint32_t *len) {
    return jc_go_session_resources(h, generation, out, cap, len);
}
int32_t jc_session_prepare_original_dns(uint64_t h, const uint8_t *in, uint32_t len, uint64_t *generation) {
    return jc_go_session_prepare_original_dns(h, (uint8_t *)in, len, generation);
}
int32_t jc_session_attach_tun(uint64_t h, uint64_t generation, int32_t fd, uint32_t mtu) {
    return jc_go_session_attach_tun(h, generation, fd, mtu);
}
int32_t jc_session_attach_tun_dns(uint64_t h, uint64_t generation, int32_t fd, uint32_t mtu) {
    return jc_go_session_attach_tun_dns(h, generation, fd, mtu);
}
int32_t jc_session_attach_windows_pipe(uint64_t h, uint64_t generation, uint64_t pipe, uint32_t helper_pid, uint32_t mtu, uint32_t source, uint32_t peer, uint32_t publish_dns_routes) {
    return jc_go_session_attach_windows_pipe(h, generation, pipe, helper_pid, mtu, source, peer, publish_dns_routes);
}
int32_t jc_session_ack_dns_routes(uint64_t h, uint64_t generation, uint64_t request, uint32_t applied) {
    return jc_go_session_ack_dns_routes(h, generation, request, applied);
}
int32_t jc_session_stop(uint64_t h, uint32_t wait) { return jc_go_session_stop(h, wait); }
int32_t jc_session_destroy(uint64_t h, uint32_t wait) { return jc_go_session_destroy(h, wait); }
