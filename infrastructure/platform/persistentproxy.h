#pragma once
#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyjournal.h"
#include <optional>

// Native/storage operations require the platform ownership lock; initial scope binding performs no I/O.
class PersistentProxyBackend final : public SystemProxyBackend
{
public:
    static QString credentialKey();
#ifdef Q_OS_WIN
    PersistentProxyBackend(CredentialStore &credentials, QString key, WindowsProxyApi api = {});
#elif defined(Q_OS_MACOS)
    PersistentProxyBackend(CredentialStore &credentials, QString key, MacProxyApi api = {});
#else
    PersistentProxyBackend(CredentialStore &credentials, QString key,
        PlatformCommandRunner runner = [](const QString &p,const QStringList &a) { return runPlatformCommand(p,a); });
#endif
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
    PlatformOperationResult beginRecovery(const QString &owner, bool resume) override;
    PlatformOperationResult configureRecovery(const QString &owner, bool resume);
private:
    PlatformOperationResult recover();
    PlatformOperationResult complete();
    PlatformOperationResult loadCompletion();
    PlatformOperationResult finishUnowned();
    ProxyRecoveryJournal journal, completion;
    PlatformSystemProxyBackend native;
    QString owner;
    QJsonObject confirmation;
    bool resuming = false, confirmed = false, completionLoaded = false;
    bool initialized = false, recovering = false;
    std::optional<PlatformOperationResult> rejected;
};
