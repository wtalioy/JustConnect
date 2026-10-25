#pragma once
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/process/command.h"

// Blocking, read-only; the production runner uses the adjacent native MI reader.
DnsSnapshot readWindowsDnsSnapshot(const PlatformCommandRunner &runner = {});
