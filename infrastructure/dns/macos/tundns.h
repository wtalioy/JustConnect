#pragma once
#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/process/command.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <QStringList>
#include <utility>

// Apple VPN.DNS defines 1 as supplemental routing without adding search domains.
inline constexpr int MacDnsNoSearch = 1;
inline CFStringRef macDnsNoSearchKey() { return CFSTR("SupplementalMatchDomainsNoSearch"); }

class MacTunDns
{
public:
    ~MacTunDns() { restore(); }
    using AddTemporary = decltype(&SCDynamicStoreAddTemporaryValue);
    explicit MacTunDns(AddTemporary add = SCDynamicStoreAddTemporaryValue,PlatformCommandRunner inspect = {})
        : add(add),inspect(std::move(inspect)) {}
    MacTunDns(const MacTunDns &) = delete;
    MacTunDns &operator=(const MacTunDns &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QStringList &domains);
    // Closing this dedicated session removes only its still-owned temporary keys.
    void restore();
    static QJsonObject properties(const QString &peer,const QStringList &domains);
    QJsonObject snapshot() const { return applied; }
private:
    SCDynamicStoreRef store = nullptr;
    QJsonObject applied;
    AddTemporary add;
    PlatformCommandRunner inspect;
};
