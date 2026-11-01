#pragma once
#include "application/dnssnapshot.h"
#include <functional>

// The DNS protocol default for native configurations that encode an unspecified port.
inline constexpr quint16 DnsServerPort = 53;

// Blocking, read-only; invoke on a worker, never on the GUI thread.
DnsSnapshot readSystemDnsSnapshot();

// Retains Windows DNS facts only while native configuration/interface watches remain unchanged.
std::function<DnsSnapshot()> observeSystemDnsSnapshot();
