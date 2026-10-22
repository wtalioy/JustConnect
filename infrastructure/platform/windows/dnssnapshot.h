#pragma once
#include "infrastructure/platform/dnssnapshot.h"
#include "infrastructure/platform/platformcommand.h"

// Blocking, read-only; the production runner uses the adjacent native MI reader.
DnsSnapshot readWindowsDnsSnapshot(const PlatformCommandRunner &runner = {});
