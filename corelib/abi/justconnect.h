#ifndef JUSTCONNECT_CORE_ABI_H
#define JUSTCONNECT_CORE_ABI_H
#include "constants.h"

#if defined(_WIN32) && defined(JC_BUILDING)
#define JC_API __declspec(dllexport)
#else
#define JC_API
#endif
#ifdef __cplusplus
extern "C" {
#endif

/* ABI/schema v1; JSON bytes are UTF-8, length-delimited, without a trailing NUL.
 * Inputs are borrowed read-only during the call and copied before returning.
 * Nonzero lengths/capacities require valid, non-overlapping caller memory.
 * Outputs and scalar pointers are caller-owned; Go pointers never escape.
 * All length/handle/generation outputs are zeroed on error, except required
 * length on JC_BUFFER_TOO_SMALL. That result never writes or consumes an event.
 * Functions may run concurrently. See docs/CORE-ABI.md for lifecycle rules.
 */
JC_API uint32_t jc_abi_version(void);
JC_API int32_t jc_build_info(uint32_t abi, uint8_t *output, uint32_t capacity, uint32_t *length);
/* Read current interfaces, IP routes and available policy rules, without modifying network state. */
JC_API int32_t jc_network_snapshot(uint32_t abi, uint8_t *output, uint32_t capacity, uint32_t *length);
/* Pure validation: no session, listeners, DNS or network operations. */
JC_API int32_t jc_config_validate(uint32_t abi, const uint8_t *config, uint32_t length);
JC_API int32_t jc_session_create(uint32_t abi, uint64_t *handle);
JC_API int32_t jc_session_start(uint64_t handle, const uint8_t *config, uint32_t length, uint64_t *generation);
JC_API int32_t jc_session_read(uint64_t handle, uint32_t wait_ms, uint8_t *output, uint32_t capacity, uint32_t *length);
JC_API int32_t jc_session_respond(uint64_t handle, const uint8_t *response, uint32_t length);
/* Atomically replace protection rules for new connections; output the applied generation. */
JC_API int32_t jc_session_update_policy(uint64_t handle, const uint8_t *policy, uint32_t length, uint64_t *generation);
/* Read parsed campus resources for the requested active generation. */
JC_API int32_t jc_session_resources(uint64_t handle, uint64_t generation, uint8_t *output, uint32_t capacity, uint32_t *length);
/* Borrow a validated, nonblocking Linux raw IPv4 TUN fd for the ready generation.
 * Success owns a CLOEXEC duplicate until stop; the original fd and its flags remain
 * caller-owned. Address/routes/DNS and fd namespace ownership belong to the helper.
 * Other platforms and the fixture driver return JC_UNSUPPORTED.
 */
JC_API int32_t jc_session_attach_tun(uint64_t handle, uint64_t generation, int32_t fd, uint32_t mtu);
/* Stop cancels before waiting; timeout retains the active slot until cleanup.
 * Destroy invalidates only after cleanup. Retry after timeout; repeated destroy
 * succeeds for issued handles. No library unload while the host is alive.
 */
JC_API int32_t jc_session_stop(uint64_t handle, uint32_t wait_ms);
JC_API int32_t jc_session_destroy(uint64_t handle, uint32_t wait_ms);

#ifdef __cplusplus
}
#endif
#endif
