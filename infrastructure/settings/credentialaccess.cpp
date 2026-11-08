#include "credentialaccess.h"
#include "application/savedconnectionservice.h"
#include "application/defaultsettings.h"
#include <QSettings>
#include <QFileInfo>
#include "application/settingsmigrator.h"
#include <QtConcurrent>

CredentialAccess::CredentialAccess(std::unique_ptr<CredentialStore> store,QObject *parent)
    :QObject(parent),store(std::move(store)) {pool.setMaxThreadCount(1);}
CredentialAccess::~CredentialAccess() {pool.waitForDone();}
CredentialSource CredentialAccess::source(QSettings &settings,const QString &legacyCachePath) {
    settings.sync();
    const bool valid=settings.status()==QSettings::NoError
        && (!QFileInfo::exists(settings.fileName()) || SettingsMigrator::readableFile(settings.fileName()));
    const auto scope = valid ? ConnectionCredentialVault::ensureScope(settings) : QString();
    const auto publicValues = DefaultSettings::publicValues(settings);
    return {settings.fileName(), scope, legacyCachePath, SavedConnectionService::load(publicValues), publicValues};
}
bool CredentialAccess::matches(const CredentialSource &source,const QSettings &settings) {
    return !source.scope.isEmpty() && settings.status()==QSettings::NoError && source.path==settings.fileName()
        && source.scope==settings.value(ConnectionCredentialVault::ScopeSetting).toString()
        && source.connectionOptions.authenticationIdentity()==SavedConnectionService::load(settings).authenticationIdentity();
}
bool CredentialAccess::isBusy(const QString &path) const {return pending.value(path)>0;}
bool CredentialAccess::isSaving(const QString &path) const {return pendingSaves.value(path)>0;}
void CredentialAccess::begin(const QString &path,bool saving) {++pending[path];if(saving)++pendingSaves[path];}
void CredentialAccess::end(const QString &path,bool saving) {
    if (--pending[path]==0) pending.remove(path);
    if (saving && --pendingSaves[path]==0) pendingSaves.remove(path);
}
CredentialResult CredentialAccess::checkSource(const CredentialSource &source,QSettings &settings,bool unchangedPublic) {
    settings.sync();
    if (settings.status()!=QSettings::NoError
        || (QFileInfo::exists(settings.fileName()) && !SettingsMigrator::readableFile(settings.fileName()))) return {CredentialStatus::Failed,{}};
    const bool current=matches(source,settings) && (!unchangedPublic || source.publicValues==DefaultSettings::publicValues(settings));
    return {current ? CredentialStatus::Success : CredentialStatus::Cancelled,{}};
}
CredentialResult CredentialAccess::prepare(const CredentialSource &source,QSettings &settings,ConnectionCredentialVault &credentials,bool unchangedPublic) {
    const auto current=checkSource(source,settings,unchangedPublic);
    if (!current.succeeded()) return current;
    auto result=credentials.migrate(settings,source.scope,source.connectionOptions);
    if (!result.succeeded()) return result;
    if (!source.legacyCachePath.isEmpty()) {
        result=credentials.quarantine(source.legacyCachePath,source.scope);
        if (!result.succeeded() && result.status!=CredentialStatus::NotFound) return result;
    }
    return checkSource(source,settings,unchangedPublic);
}
QFuture<CredentialLoadResult> CredentialAccess::load(const CredentialSource &source) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        ConnectionCredentialVault credentials(*store);
        CredentialLoadResult loaded;
        loaded.result=prepare(source,settings,credentials);
        if (!loaded.result.succeeded()) return loaded;
        if (ConnectionCredentialVault::key(source.scope,source.connectionOptions).isEmpty()) return CredentialLoadResult{{CredentialStatus::NotFound,{}},{}};
        loaded.result=credentials.load(source.scope,source.connectionOptions,loaded.credentials);
        const auto current=checkSource(source,settings);
        if (!current.succeeded()) return CredentialLoadResult{current,{}};
        return loaded;
    }).then(this,[this,path=source.path](const CredentialLoadResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::save(const CredentialSource &source,const ConnectionOptions &connectionOptions,bool updateCredentials,const QVariantMap &publicChanges) {
    const bool saving=!publicChanges.isEmpty();begin(source.path,saving);
    return QtConcurrent::run(&pool,[this,source,connectionOptions,updateCredentials,publicChanges] {
        if (!SavedConnectionService::validPublicChanges(publicChanges)) return CredentialResult{CredentialStatus::InvalidArgument,{}};
        QSettings settings(source.path,QSettings::IniFormat);
        ConnectionCredentialVault credentials(*store);
        auto result=checkSource(source,settings,true);
        if (!result.succeeded()) return result;
        result=prepare(source,settings,credentials,true);
        if (!result.succeeded() && result.status!=CredentialStatus::Cancelled && !updateCredentials && settings.status()==QSettings::NoError) {
            const bool pendingLegacy=ConnectionCredentialVault::hasLegacyCredentials(settings);
            if (!pendingLegacy || connectionOptions.authenticationIdentity()==source.connectionOptions.authenticationIdentity())
                result={CredentialStatus::Success,{}};
        }
        if (result.succeeded() && updateCredentials) result=credentials.save(source.scope,connectionOptions);
        if (!result.succeeded()) return result;
        result=checkSource(source,settings,true);
        if (!result.succeeded()) return result;
        return CredentialResult{SavedConnectionService::writePublic(settings,publicChanges) ? CredentialStatus::Success : CredentialStatus::Failed,{}};
    }).then(this,[this,path=source.path,saving](const CredentialResult &result) {
        end(path,saving);
        if (result.succeeded() && saving) emit configurationSaved(path);
        return result;
    });
}
QFuture<CredentialResult> CredentialAccess::migrate(const CredentialSource &source) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        ConnectionCredentialVault credentials(*store);
        return prepare(source,settings,credentials,true);
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::clear(const CredentialSource &source) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        const auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return current;
        ConnectionCredentialVault credentials(*store);
        const auto result=credentials.clear(settings,source.scope,source.connectionOptions);
        return result.succeeded() ? checkSource(source,settings,true) : result;
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}

quint64 CredentialAccess::authenticationCacheRevision(const CredentialSource &source) const {
    QMutexLocker lock(&cacheMutex);
    return cacheRevisions.value(ConnectionCredentialVault::authenticationCacheKey(source.scope,source.connectionOptions));
}
QFuture<AuthenticationCacheLoadResult> CredentialAccess::loadAuthenticationCache(const CredentialSource &source) {
    const auto revision=authenticationCacheRevision(source);
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source,revision] {
        QSettings settings(source.path,QSettings::IniFormat);
        AuthenticationCacheLoadResult loaded;loaded.revision=revision;
        loaded.result=checkSource(source,settings,true);
        if (!loaded.result.succeeded()) return loaded;
        if (authenticationCacheRevision(source)!=revision) return AuthenticationCacheLoadResult{{CredentialStatus::Cancelled,{}},{},revision};
        if (ConnectionCredentialVault::authenticationCacheKey(source.scope,source.connectionOptions).isEmpty()) return AuthenticationCacheLoadResult{{CredentialStatus::NotFound,{}},{},revision};
        ConnectionCredentialVault credentials(*store);
        loaded.result=credentials.loadAuthenticationCache(source.scope,source.connectionOptions,loaded.cache);
        const auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return AuthenticationCacheLoadResult{current,{},revision};
        if (authenticationCacheRevision(source)!=revision) return AuthenticationCacheLoadResult{{CredentialStatus::Cancelled,{}},{},revision};
        return loaded;
    }).then(this,[this,path=source.path](const AuthenticationCacheLoadResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::saveAuthenticationCache(const CredentialSource &source,const AuthenticationCache &cache,quint64 revision) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source,cache,revision] {
        QSettings settings(source.path,QSettings::IniFormat);
        auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return current;
        if (authenticationCacheRevision(source)!=revision) return CredentialResult{CredentialStatus::Cancelled,{}};
        ConnectionCredentialVault credentials(*store);
        const auto saved=credentials.saveAuthenticationCache(source.scope,source.connectionOptions,cache);
        if (authenticationCacheRevision(source)!=revision) return CredentialResult{CredentialStatus::Cancelled,{}};
        current=checkSource(source,settings,true);
        return current.succeeded() ? saved : current;
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::clearAuthenticationCache(const CredentialSource &source) {
    const auto key=ConnectionCredentialVault::authenticationCacheKey(source.scope,source.connectionOptions);
    if (!key.isEmpty()) {
        QMutexLocker lock(&cacheMutex);
        ++cacheRevisions[key]; // Invalidate old callbacks before queued native I/O completes.
    }
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        const auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return current;
        ConnectionCredentialVault credentials(*store);
        const auto cleared=credentials.clearAuthenticationCache(source.scope,source.connectionOptions);
        return cleared.succeeded() ? checkSource(source,settings,true) : cleared;
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}

QFuture<CredentialResult> CredentialAccess::clearLegacyCache(const CredentialSource &source) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        const auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return current;
        ConnectionCredentialVault credentials(*store);
        const auto result=credentials.clearLegacyCache(source.legacyCachePath,source.scope);
        return result.succeeded() ? checkSource(source,settings,true) : result;
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}
