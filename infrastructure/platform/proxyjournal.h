#pragma once
#include "application/credentialstore.h"
#include <optional>

// Credential APIs lack compare-and-swap; callers hold the platform ownership lock and validate native records.
class ProxyRecoveryJournal
{
public:
    ProxyRecoveryJournal(CredentialStore &store, QString key) : credentials(store), key(std::move(key)) {}
    ProxyRecoveryJournal(const ProxyRecoveryJournal &) = delete;
    ProxyRecoveryJournal &operator=(const ProxyRecoveryJournal &) = delete;
    CredentialResult load();
    CredentialResult checkpoint(const QByteArray &record);
private:
    CredentialStore &credentials;
    const QString key;
    QByteArray known;
    std::optional<QByteArray> pending;
    bool loaded = false, present = false, pendingRemoval = false, removalUncertain = false;
};
