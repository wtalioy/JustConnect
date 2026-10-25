#pragma once
#include <cstddef>
// Bound native DNS control records consistently across system backends.
inline constexpr std::size_t NetworkDnsDomainLimit = 4096;
