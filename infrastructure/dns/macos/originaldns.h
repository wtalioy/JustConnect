#pragma once
#include "application/dnssnapshot.h"
#include "infrastructure/process/command.h"
#include <QJsonArray>
#include <QUuid>
#include <SystemConfiguration/SystemConfiguration.h>
#include <functional>
#include <optional>

DnsSnapshot readMacDnsPreferences(const QString &service);

// Durable preferences keep original DNS redirected until capture has been released, including after a helper crash.
class MacOriginalDns
{
public:
    using Checkpoint = std::function<PlatformOperationResult(const QJsonObject &)>;
    using StateReader = std::function<std::optional<QJsonValue>(const QString &service)>;
    explicit MacOriginalDns(SCPreferencesRef preferences = nullptr,PlatformCommandRunner inspect = {},StateReader readState = {});
    ~MacOriginalDns();
    MacOriginalDns(const MacOriginalDns &) = delete;
    MacOriginalDns &operator=(const MacOriginalDns &) = delete;
    PlatformOperationResult apply(const QUuid &owner,const QJsonArray &sources,const Checkpoint &checkpoint);
    PlatformOperationResult restore(const QUuid &owner,const QJsonObject &record,const Checkpoint &checkpoint);
    QJsonObject snapshot() const { return installed; }
    static bool valid(const QUuid &owner,const QJsonObject &record);
    static std::optional<QJsonObject> properties(const QJsonObject &entry,bool original);
private:
    SCPreferencesRef preferences = nullptr;
    QJsonObject installed;
    PlatformCommandRunner inspect;
    StateReader readState;
};
