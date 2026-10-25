#include "infrastructure/dns/dnssnapshot.h"
#ifdef Q_OS_WIN
#include "infrastructure/dns/windows/dnssnapshot.h"
#elif defined(Q_OS_MACOS)
#include "infrastructure/dns/macos/dnssnapshot.h"
#elif defined(Q_OS_LINUX)
#include "infrastructure/dns/linux/dnssnapshot.h"
#endif

DnsSnapshot readSystemDnsSnapshot()
{
#ifdef Q_OS_WIN
    return readWindowsDnsSnapshot();
#elif defined(Q_OS_MACOS)
    return readMacDnsSnapshot();
#elif defined(Q_OS_LINUX)
    return readLinuxDnsSnapshot();
#else
    return {{PlatformOperationResult::Status::Unsupported, QStringLiteral("DNS snapshot unavailable")}, {}};
#endif
}
