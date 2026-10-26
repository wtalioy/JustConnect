#pragma once
#include "application/dnssnapshot.h"

// The DNS protocol default for native configurations that encode an unspecified port.
inline constexpr quint16 DnsServerPort = 53;

// Blocking, read-only; invoke on a worker, never on the GUI thread.
DnsSnapshot readSystemDnsSnapshot();
