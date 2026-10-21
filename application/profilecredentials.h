#pragma once
#include "application/credentialstore.h"
#include "core/connectionprofile.h"
#include "core/authenticationcache.h"

class QSettings;

// Native calls are synchronous; callers serialize them outside the GUI thread.
class ProfileCredentials {
public:
    explicit ProfileCredentials(CredentialStore &store):store(store) {}
    static constexpr auto ScopeSetting = "Credential/StoreID";
    static bool hasLegacyCredentials(const QSettings &settings);
    static QString ensureScope(QSettings &settings);
    static QString key(const QString &scope,const ConnectionProfile &profile);
    static QString authenticationCacheKey(const QString &scope,const ConnectionProfile &profile);
    static QString legacyCacheKey(const QString &scope);

    CredentialResult load(const QString &scope,const ConnectionProfile &profile,ConnectionCredentials &credentials);
    CredentialResult save(const QString &scope,const ConnectionProfile &profile);
    CredentialResult clear(QSettings &settings,const QString &scope,const ConnectionProfile &profile);
    CredentialResult loadAuthenticationCache(const QString &scope,const ConnectionProfile &profile,AuthenticationCache &cache);
    CredentialResult saveAuthenticationCache(const QString &scope,const ConnectionProfile &profile,const AuthenticationCache &cache);
    CredentialResult clearAuthenticationCache(const QString &scope,const ConnectionProfile &profile);
    // Migrate the loaded source identity before committing any identity edits.
    CredentialResult migrate(QSettings &settings,const QString &scope,const ConnectionProfile &profile);
    // Old cache has no reliable account binding; seal it without using it for login.
    CredentialResult quarantine(const QString &path,const QString &scope);
    CredentialResult clearLegacyCache(const QString &path,const QString &scope);
private:
    CredentialStore &store;
    CredentialResult removeVerified(const QString &key);
    CredentialResult preserveVerified(const QString &key,const QByteArray &value);
    CredentialResult writeVerified(const QString &key,const QByteArray &value);
};
