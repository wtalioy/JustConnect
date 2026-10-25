#pragma once
#include "application/dnssnapshot.h"

// Blocking, read-only; invoke on a worker, never on the GUI thread.
DnsSnapshot readSystemDnsSnapshot();
