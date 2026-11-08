#include "authenticationcachecoordinator.h"
#include "application/connectionsession.h"
#include "application/connectioncredentialvault.h"
#include "presentation/presentationhelpers.h"
#include <utility>

AuthenticationCacheCoordinator::AuthenticationCacheCoordinator(ConnectionSession *session,CredentialAccess *credentials,SourceProvider sourceProvider,QObject *parent)
    : QObject(parent),connectionSession(session),credentials(credentials),credentialSourceProvider(std::move(sourceProvider))
{
    connect(session,&ConnectionSession::authenticationCacheUpdated,this,&AuthenticationCacheCoordinator::rememberAuthentication);
    connect(session,&ConnectionSession::authenticationCacheInvalidated,this,&AuthenticationCacheCoordinator::invalidateAuthenticationCache);
    connect(session,&ConnectionSession::diagnostic,this,[this](const QString &code) {
        if (code=="persistence_failed" && cacheSource && !cacheWarningShown) {
            cacheWarningShown=true;
            emit warning(tr("The core could not provide authentication data that can be saved safely. You may need to sign in again later."));
        }
    });
}

ConnectionOptions AuthenticationCacheCoordinator::prepare(ConnectionOptions connectionOptions,const CredentialSource &source,quint64 revision)
{
    ++cacheGeneration;bindingCacheAccount=false;pendingCache={};cacheWarningShown=false;cacheSource.reset();
    if (connectionOptions.behavior.rememberAuthentication && !source.scope.isEmpty()
        && connectionOptions.authenticationIdentity()==source.connectionOptions.authenticationIdentity()) {
        cacheSource=source;cacheRevision=revision;
        if (revision!=credentials->authenticationCacheRevision(source)) connectionOptions.authenticationCache={};
    } else {connectionOptions.behavior.rememberAuthentication=false;connectionOptions.authenticationCache={};}
    return connectionOptions;
}

void AuthenticationCacheCoordinator::reportCacheFailure(CredentialStatus status)
{
    if (cacheWarningShown || status==CredentialStatus::Success || status==CredentialStatus::Cancelled) return;
    cacheWarningShown=true;
    emit warning(PresentationHelpers::credentialOperationMessage(status)+tr("\nThis connection remains usable. You may need to sign in again later."));
}
void AuthenticationCacheCoordinator::rememberAuthentication(const AuthenticationCache &cache)
{
    if (!cacheSource) return;
    const auto source=*cacheSource;const auto generation=cacheGeneration;
    const bool external=source.connectionOptions.endpoint.authType=="cas" || source.connectionOptions.endpoint.authType=="httpsOauth2";
    if (external && !source.connectionOptions.credentials.username.isEmpty() && !source.connectionOptions.matchesCacheAccount(cache.account)) {
        connectionSession->forgetAuthenticationCache();cacheSource.reset();++cacheGeneration;emit forgotten();
        emit warning(tr("The signed-in account differs from the account set for this connection. Confirm the account before reconnecting."));return;
    }
    if (external && source.connectionOptions.credentials.username.isEmpty()) {
        pendingCache=cache;
        if (bindingCacheAccount) return;
        bindingCacheAccount=true;
        auto connectionOptions=source.connectionOptions;connectionOptions.credentials.username=cache.account;
        credentials->save(source,connectionOptions,false,{{"Credential/Username",cache.account}}).then(this,[this,source,connectionOptions,generation](const CredentialResult &result) {
            if (generation!=cacheGeneration || !cacheSource) return;
            bindingCacheAccount=false;
            if (!result.succeeded()) {pendingCache={};reportCacheFailure(result.status);return;}
            const auto current=credentialSourceProvider();
            if (current.path!=source.path || current.scope!=source.scope || current.connectionOptions.authenticationIdentity()!=connectionOptions.authenticationIdentity()) {pendingCache={};return;}
            cacheSource=current;cacheRevision=credentials->authenticationCacheRevision(current);
            const auto latest=std::exchange(pendingCache,{});
            rememberAuthentication(latest);
        });return;
    }
    credentials->saveAuthenticationCache(source,cache,cacheRevision).then(this,[this,generation](const CredentialResult &result) {
        if (generation==cacheGeneration) reportCacheFailure(result.status);
    });
}
void AuthenticationCacheCoordinator::invalidateAuthenticationCache()
{
    ++cacheGeneration;bindingCacheAccount=false;pendingCache={};
    if (!cacheSource || ConnectionCredentialVault::authenticationCacheKey(cacheSource->scope,cacheSource->connectionOptions).isEmpty()) return;
    const auto generation=cacheGeneration;
    credentials->clearAuthenticationCache(*cacheSource).then(this,[this,generation](const CredentialResult &result) {
        if (generation==cacheGeneration) reportCacheFailure(result.status);
    });
    cacheRevision=credentials->authenticationCacheRevision(*cacheSource);
}
QFuture<CredentialResult> AuthenticationCacheCoordinator::clear(const CredentialSource &source)
{
    if (cacheSource && ConnectionCredentialVault::authenticationCacheKey(cacheSource->scope,cacheSource->connectionOptions)==ConnectionCredentialVault::authenticationCacheKey(source.scope,source.connectionOptions)) {
        connectionSession->forgetAuthenticationCache();cacheSource.reset();++cacheGeneration;bindingCacheAccount=false;pendingCache={};emit forgotten();
    }
    return credentials->clearAuthenticationCache(source);
}
