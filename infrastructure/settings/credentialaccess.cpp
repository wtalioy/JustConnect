#include "credentialaccess.h"
#include "settingsprofileloader.h"
#include <QSettings>
#include <QtConcurrent>

namespace {
ConnectionProfile publicProfile(const QSettings &settings) {
    auto profile=SettingsProfileLoader::load(settings);
    profile.credentials.password.clear();profile.credentials.totpSecret.clear();
    return profile;
}
}
CredentialAccess::CredentialAccess(std::unique_ptr<CredentialStore> store,QObject *parent)
    :QObject(parent),store(std::move(store)) {pool.setMaxThreadCount(1);}
CredentialAccess::~CredentialAccess() {pool.waitForDone();}
CredentialSource CredentialAccess::source(QSettings &settings,const QString &legacyCachePath) {
    settings.sync();
    CredentialSource source{settings.fileName(),ProfileCredentials::ensureScope(settings),legacyCachePath,publicProfile(settings)};
    return source;
}
bool CredentialAccess::matches(const CredentialSource &source,const QSettings &settings) {
    return !source.scope.isEmpty() && settings.status()==QSettings::NoError && source.path==settings.fileName()
        && source.scope==settings.value(ProfileCredentials::ScopeSetting).toString()
        && source.profile.hasSameAuthentication(publicProfile(settings));
}
CredentialResult CredentialAccess::checkSource(const CredentialSource &source,QSettings &settings) {
    settings.sync();
    if (settings.status()!=QSettings::NoError) return {CredentialStatus::Failed,{}};
    return {matches(source,settings) ? CredentialStatus::Success : CredentialStatus::Cancelled,{}};
}
CredentialResult CredentialAccess::prepare(const CredentialSource &source,QSettings &settings,ProfileCredentials &credentials) {
    const auto current=checkSource(source,settings);
    if (!current.succeeded()) return current;
    auto result=credentials.migrate(settings,source.scope,source.profile);
    if (!result.succeeded()) return result;
    if (!source.legacyCachePath.isEmpty()) {
        result=credentials.quarantine(source.legacyCachePath,source.scope);
        if (!result.succeeded() && result.status!=CredentialStatus::NotFound) return result;
    }
    return checkSource(source,settings);
}
QFuture<CredentialLoadResult> CredentialAccess::load(const CredentialSource &source) {
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
    });
}
QFuture<CredentialResult> CredentialAccess::save(const CredentialSource &source,const ConnectionProfile &profile,bool updateCredentials) {
    return QtConcurrent::run(&pool,[this,source,profile,updateCredentials] {
        QSettings settings(source.path,QSettings::IniFormat);
        ProfileCredentials credentials(*store);
        auto result=prepare(source,settings,credentials);
        if (!result.succeeded()) return result;
        if (updateCredentials) result=credentials.save(source.scope,profile);
        return result.succeeded() ? checkSource(source,settings) : result;
    });
}
