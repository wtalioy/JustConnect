#include "credentialaccess.h"
#include "application/profileservice.h"
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
    return {settings.fileName(),valid ? ProfileCredentials::ensureScope(settings) : QString(),legacyCachePath,ProfileService::load(settings),DefaultSettings::publicValues(settings)};
}
bool CredentialAccess::matches(const CredentialSource &source,const QSettings &settings) {
    return !source.scope.isEmpty() && settings.status()==QSettings::NoError && source.path==settings.fileName()
        && source.scope==settings.value(ProfileCredentials::ScopeSetting).toString()
        && source.profile.authenticationIdentity()==ProfileService::load(settings).authenticationIdentity();
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
CredentialResult CredentialAccess::prepare(const CredentialSource &source,QSettings &settings,ProfileCredentials &credentials,bool unchangedPublic) {
    const auto current=checkSource(source,settings,unchangedPublic);
    if (!current.succeeded()) return current;
    auto result=credentials.migrate(settings,source.scope,source.profile);
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
        ProfileCredentials credentials(*store);
        CredentialLoadResult loaded;
        loaded.result=prepare(source,settings,credentials);
        if (!loaded.result.succeeded()) return loaded;
        if (ProfileCredentials::key(source.scope,source.profile).isEmpty()) return CredentialLoadResult{{CredentialStatus::NotFound,{}},{}};
        loaded.result=credentials.load(source.scope,source.profile,loaded.credentials);
        const auto current=checkSource(source,settings);
        if (!current.succeeded()) return CredentialLoadResult{current,{}};
        return loaded;
    }).then(this,[this,path=source.path](const CredentialLoadResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::save(const CredentialSource &source,const ConnectionProfile &profile,bool updateCredentials,const QVariantMap &publicChanges) {
    const bool saving=!publicChanges.isEmpty();begin(source.path,saving);
    return QtConcurrent::run(&pool,[this,source,profile,updateCredentials,publicChanges] {
        if (!ProfileService::validPublicChanges(publicChanges)) return CredentialResult{CredentialStatus::InvalidArgument,{}};
        QSettings settings(source.path,QSettings::IniFormat);
        ProfileCredentials credentials(*store);
        auto result=checkSource(source,settings,true);
        if (!result.succeeded()) return result;
        result=prepare(source,settings,credentials,true);
        if (!result.succeeded() && result.status!=CredentialStatus::Cancelled && !updateCredentials && settings.status()==QSettings::NoError) {
            const bool pendingLegacy=ProfileCredentials::hasLegacyCredentials(settings);
            if (!pendingLegacy || profile.authenticationIdentity()==source.profile.authenticationIdentity())
                result={CredentialStatus::Success,{}};
        }
        if (result.succeeded() && updateCredentials) result=credentials.save(source.scope,profile);
        if (!result.succeeded()) return result;
        result=checkSource(source,settings,true);
        if (!result.succeeded()) return result;
        return CredentialResult{ProfileService::writePublic(settings,publicChanges) ? CredentialStatus::Success : CredentialStatus::Failed,{}};
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
        ProfileCredentials credentials(*store);
        return prepare(source,settings,credentials,true);
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}
QFuture<CredentialResult> CredentialAccess::clear(const CredentialSource &source) {
    begin(source.path,false);
    return QtConcurrent::run(&pool,[this,source] {
        QSettings settings(source.path,QSettings::IniFormat);
        const auto current=checkSource(source,settings,true);
        if (!current.succeeded()) return current;
        ProfileCredentials credentials(*store);
        const auto result=credentials.clear(settings,source.scope,source.profile);
        return result.succeeded() ? checkSource(source,settings,true) : result;
    }).then(this,[this,path=source.path](const CredentialResult &result){end(path,false);return result;});
}
