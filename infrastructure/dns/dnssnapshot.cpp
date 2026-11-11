#include "infrastructure/dns/dnssnapshot.h"
#if defined(Q_OS_WIN)
#include "infrastructure/dns/windows/dnssnapshot.h"
#include "infrastructure/dns/windows/observedsnapshot.h"
#else
#include "infrastructure/dns/macos/dnssnapshot.h"
#endif

DnsSnapshot readSystemDnsSnapshot()
{
#if defined(Q_OS_WIN)
    return readWindowsDnsSnapshot();
#else
    return readMacDnsSnapshot();
#endif
}

std::function<DnsSnapshot()> observeSystemDnsSnapshot()
{
#if defined(Q_OS_WIN)
    auto observation = std::make_shared<WindowsObservedDnsSnapshot>(readSystemDnsSnapshot);
    return [observation] { return observation->read(); };
#else
    return readSystemDnsSnapshot;
#endif
}
