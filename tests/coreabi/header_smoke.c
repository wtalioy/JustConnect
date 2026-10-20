#include "justconnect.h"
_Static_assert(sizeof(uint64_t) == 8, "handle width");
_Static_assert(sizeof(int32_t) == 4, "status width");
int32_t jc_c_header_smoke(uint32_t (*query)(void)) {
    return query() == JC_ABI_VERSION ? JC_OK : JC_ABI_MISMATCH;
}
