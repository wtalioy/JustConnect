#include "infrastructure/dns/dnssnapshot.h"
#if defined(Q_OS_WIN)
#include "infrastructure/dns/windows/dnssnapshot.h"
#include "infrastructure/dns/windows/observedsnapshot.h"
#elif defined(Q_OS_LINUX)
#include "infrastructure/dns/linux/dnssnapshot.h"
#else
#include "infrastructure/dns/macos/dnssnapshot.h"
#endif

DnsSnapshot readSystemDnsSnapshot()
{
#if defined(Q_OS_WIN)
    return readWindowsDnsSnapshot();
#elif defined(Q_OS_LINUX)
    return readLinuxDnsSnapshot();
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
