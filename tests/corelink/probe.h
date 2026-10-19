#pragma once
#include <stdint.h>

/* S1-06 probe only; the production ABI is defined in S1-03. */
#ifdef __cplusplus
extern "C" {
#endif
uint32_t jc_probe_abi(void);
uint64_t jc_probe_create(const uint8_t *input, uint32_t length);
int32_t jc_probe_read(uint64_t handle, uint8_t *output, uint32_t capacity, uint32_t *length);
int32_t jc_probe_destroy(uint64_t handle);
uint32_t jc_probe_live(void);
#ifdef __cplusplus
}
#endif
