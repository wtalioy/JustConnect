#pragma once
#include "infrastructure/platform/tundevice.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <QStringList>

class MacTunDns
{
public:
    ~MacTunDns() { restore(); }
    using AddTemporary = decltype(&SCDynamicStoreAddTemporaryValue);
    explicit MacTunDns(AddTemporary add = SCDynamicStoreAddTemporaryValue) : add(add) {}
    MacTunDns(const MacTunDns &) = delete;
    MacTunDns &operator=(const MacTunDns &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QStringList &domains);
    // Closing this dedicated session removes only its still-owned temporary keys.
    void restore();
    QJsonObject snapshot() const { return applied; }
private:
    SCDynamicStoreRef store = nullptr;
    QJsonObject applied;
    AddTemporary add;
};
