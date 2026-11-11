#pragma once

#include "application/credentialstore.h"

class MacProxyReceiptStore final : public CredentialStore
{
public:
    explicit MacProxyReceiptStore(const QString &directory);
    CredentialResult read(const QString &key) override;
    CredentialResult write(const QString &key, const QByteArray &value) override;
    CredentialResult remove(const QString &key) override;
private:
    QString path;
};
