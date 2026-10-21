#include "authenticationcachecoordinator.h"
#include "application/connectionsession.h"
#include "application/profilecredentials.h"
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
            emit warning("核心未能提供可安全保存的认证材料，后续可能需要重新认证。");
        }
    });
}

ConnectionProfile AuthenticationCacheCoordinator::prepare(ConnectionProfile profile,const CredentialSource &source,quint64 revision)
{
    ++cacheGeneration;bindingCacheAccount=false;pendingCache={};cacheWarningShown=false;cacheSource.reset();
    if (profile.behavior.rememberAuthentication && !source.scope.isEmpty()
        && profile.authenticationIdentity()==source.profile.authenticationIdentity()) {
        cacheSource=source;cacheRevision=revision;
        if (revision!=credentials->authenticationCacheRevision(source)) profile.authenticationCache={};
    } else {profile.behavior.rememberAuthentication=false;profile.authenticationCache={};}
    return profile;
}

void AuthenticationCacheCoordinator::reportCacheFailure(CredentialStatus status)
{
    if (cacheWarningShown || status==CredentialStatus::Success || status==CredentialStatus::Cancelled) return;
    cacheWarningShown=true;
    emit warning(PresentationHelpers::credentialOperationMessage(status)+"\n本次连接仍可使用，后续可能需要重新认证。");
}
void AuthenticationCacheCoordinator::rememberAuthentication(const AuthenticationCache &cache)
{
    if (!cacheSource) return;
    const auto source=*cacheSource;const auto generation=cacheGeneration;
    const bool external=source.profile.endpoint.authType=="cas" || source.profile.endpoint.authType=="httpsOauth2";
    if (external && !source.profile.credentials.username.isEmpty() && !source.profile.matchesCacheAccount(cache.account)) {
        connectionSession->forgetAuthenticationCache();cacheSource.reset();++cacheGeneration;emit forgotten();
        emit warning("本次登录账户与配置中选定的账户不同，请确认账户后重新连接。");return;
    }
    if (external && source.profile.credentials.username.isEmpty()) {
        pendingCache=cache;
        if (bindingCacheAccount) return;
        bindingCacheAccount=true;
        auto profile=source.profile;profile.credentials.username=cache.account;
        credentials->save(source,profile,false,{{"Credential/Username",cache.account}}).then(this,[this,source,profile,generation](const CredentialResult &result) {
            if (generation!=cacheGeneration || !cacheSource) return;
            bindingCacheAccount=false;
            if (!result.succeeded()) {pendingCache={};reportCacheFailure(result.status);return;}
            const auto current=credentialSourceProvider();
            if (current.path!=source.path || current.scope!=source.scope || current.profile.authenticationIdentity()!=profile.authenticationIdentity()) {pendingCache={};return;}
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
    if (!cacheSource || ProfileCredentials::authenticationCacheKey(cacheSource->scope,cacheSource->profile).isEmpty()) return;
    const auto generation=cacheGeneration;
    credentials->clearAuthenticationCache(*cacheSource).then(this,[this,generation](const CredentialResult &result) {
        if (generation==cacheGeneration) reportCacheFailure(result.status);
    });
    cacheRevision=credentials->authenticationCacheRevision(*cacheSource);
}
QFuture<CredentialResult> AuthenticationCacheCoordinator::clear(const CredentialSource &source)
{
    if (cacheSource && ProfileCredentials::authenticationCacheKey(cacheSource->scope,cacheSource->profile)==ProfileCredentials::authenticationCacheKey(source.scope,source.profile)) {
        connectionSession->forgetAuthenticationCache();cacheSource.reset();++cacheGeneration;bindingCacheAccount=false;pendingCache={};emit forgotten();
    }
    return credentials->clearAuthenticationCache(source);
}
