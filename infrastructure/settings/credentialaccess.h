#pragma once
#include "application/profilecredentials.h"
#include <QFuture>
#include <QHash>
#include <QObject>
#include <QThreadPool>
#include <QVariantMap>
#include <memory>

struct CredentialSource {
    QString path,scope,legacyCachePath;
    ConnectionProfile profile;
    QVariantMap publicValues;
};
struct CredentialLoadResult {
    CredentialResult result;
    ConnectionCredentials credentials;
};
class CredentialAccess : public QObject {
    Q_OBJECT
public:
    explicit CredentialAccess(std::unique_ptr<CredentialStore> store,QObject *parent=nullptr);
    ~CredentialAccess() override;
    static CredentialSource source(QSettings &settings,const QString &legacyCachePath);
    static bool matches(const CredentialSource &source,const QSettings &settings);
    bool isBusy(const QString &path) const;
    bool isSaving(const QString &path) const;
    QFuture<CredentialLoadResult> load(const CredentialSource &source);
    QFuture<CredentialResult> save(const CredentialSource &source,const ConnectionProfile &profile,bool updateCredentials,const QVariantMap &publicChanges);
    QFuture<CredentialResult> migrate(const CredentialSource &source);
    QFuture<CredentialResult> clear(const CredentialSource &source);
signals:
    void configurationSaved(const QString &path);
private:
    std::unique_ptr<CredentialStore> store;
    QThreadPool pool;
    QHash<QString,int> pending,pendingSaves;
    void begin(const QString &path,bool saving);
    void end(const QString &path,bool saving);
    static CredentialResult checkSource(const CredentialSource &source,QSettings &settings,bool unchangedPublic=false);
    CredentialResult prepare(const CredentialSource &source,QSettings &settings,ProfileCredentials &credentials,bool unchangedPublic=false);
};
