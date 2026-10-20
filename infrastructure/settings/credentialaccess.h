#pragma once
#include "application/profilecredentials.h"
#include <QFuture>
#include <QObject>
#include <QThreadPool>
#include <memory>

struct CredentialSource {
    QString path,scope,legacyCachePath;
    ConnectionProfile profile;
};
struct CredentialLoadResult {
    CredentialResult result;
    ConnectionCredentials credentials;
};
class CredentialAccess : public QObject {
public:
    explicit CredentialAccess(std::unique_ptr<CredentialStore> store,QObject *parent=nullptr);
    ~CredentialAccess() override;
    static CredentialSource source(QSettings &settings,const QString &legacyCachePath);
    static bool matches(const CredentialSource &source,const QSettings &settings);
    QFuture<CredentialLoadResult> load(const CredentialSource &source);
    QFuture<CredentialResult> save(const CredentialSource &source,const ConnectionProfile &profile,bool updateCredentials);
private:
    std::unique_ptr<CredentialStore> store;
    QThreadPool pool;
    static CredentialResult checkSource(const CredentialSource &source,QSettings &settings);
    CredentialResult prepare(const CredentialSource &source,QSettings &settings,ProfileCredentials &credentials);
};
