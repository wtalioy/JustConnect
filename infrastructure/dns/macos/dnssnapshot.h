#pragma once
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/process/command.h"
#include <SystemConfiguration/SystemConfiguration.h>

using MacDnsRead = decltype(&SCDynamicStoreCopyMultiple);
// Blocking, read-only; the callback has the native Copy ownership contract.
DnsSnapshot readMacDnsSnapshot(MacDnsRead read = SCDynamicStoreCopyMultiple, PlatformCommandRunner inspect = {});
