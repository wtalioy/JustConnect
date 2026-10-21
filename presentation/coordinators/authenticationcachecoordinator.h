#ifndef AUTHENTICATIONCACHECOORDINATOR_H
#define AUTHENTICATIONCACHECOORDINATOR_H

#include <QObject>
#include <functional>
#include <optional>
#include "infrastructure/settings/credentialaccess.h"

class ConnectionSession;

// Coordinates cache persistence; widgets and connection intent stay with their owners.
class AuthenticationCacheCoordinator : public QObject
{
    Q_OBJECT
public:
    using SourceProvider=std::function<CredentialSource()>;
    AuthenticationCacheCoordinator(ConnectionSession *session,CredentialAccess *credentials,SourceProvider sourceProvider,QObject *parent=nullptr);
    ConnectionProfile prepare(ConnectionProfile profile,const CredentialSource &source,quint64 revision);
    QFuture<CredentialResult> clear(const CredentialSource &source);
    const std::optional<CredentialSource> &source() const { return cacheSource; }
    bool isBinding() const { return bindingCacheAccount; }
    bool isBindingFor(const QString &path) const { return bindingCacheAccount && cacheSource && cacheSource->path==path; }
signals:
    void warning(const QString &message);
    void forgotten();
private:
    void rememberAuthentication(const AuthenticationCache &cache);
    void invalidateAuthenticationCache();
    void reportCacheFailure(CredentialStatus status);
    ConnectionSession *connectionSession;
    CredentialAccess *credentials;
    SourceProvider credentialSourceProvider;
    std::optional<CredentialSource> cacheSource;
    quint64 cacheRevision=0,cacheGeneration=0;
    bool cacheWarningShown=false,bindingCacheAccount=false;
    AuthenticationCache pendingCache;
};
#endif
