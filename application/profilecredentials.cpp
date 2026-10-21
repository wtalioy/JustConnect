#include "profilecredentials.h"
#include "application/applicationconstants.h"
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QUuid>

namespace {
using Status=CredentialStatus;
bool validScope(const QString &scope) {
    const auto id=QUuid::fromString(scope);
    return !id.isNull() && scope==id.toString(QUuid::WithoutBraces);
}
QString digest(const QJsonArray &values) {
    return QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(values).toJson(QJsonDocument::Compact),QCryptographicHash::Sha256).toHex());
}
QString profileKey(const QString &scope,const ConnectionProfile &p,const QString &kind) {
    if (!validScope(scope) || p.endpoint.server.isEmpty() || p.endpoint.port<1 || p.endpoint.port>65535 || p.endpoint.authType.isEmpty()) return {};
    auto identity=p.authenticationIdentity();identity.prepend(scope);identity.prepend(kind);
    return digest(identity);
}
QByteArray encode(const ConnectionCredentials &credentials) {
    return QJsonDocument(QJsonObject{{"version",1},{"password",credentials.password},{"totp_secret",credentials.totpSecret}}).toJson(QJsonDocument::Compact);
}
bool decode(const QByteArray &bytes,ConnectionCredentials &credentials) {
    const auto document=QJsonDocument::fromJson(bytes);
    if (!document.isObject()) return false;
    const auto object=document.object();
    if (object.size()!=3 || object.value("version")!=QJsonValue(1)
        || !object.value("password").isString() || !object.value("totp_secret").isString()) return false;
    credentials.password=object.value("password").toString();
    credentials.totpSecret=object.value("totp_secret").toString();
    return true;
}
QString archiveKey(const QString &scope,const ConnectionProfile &profile,const QSettings &settings) {
    if (!validScope(scope)) return {};
    auto saved=profile;
    // Unconfirmed addresses identify an archive, never a login credential.
    if (saved.endpoint.server.isEmpty()) saved.endpoint.server=settings.value("JustConnect/ServerAddress").toString();
    return digest({"legacy-credentials-v1",scope,saved.authenticationIdentity()});
}
CredentialResult eraseLegacy(QSettings &settings,const QVariant &password,const QVariant &totp,const QString &username) {
    if (settings.value("Credential/Password")!=password || settings.value("Credential/TOTPSecret")!=totp
        || settings.value("Credential/Username").toString()!=username) return {Status::Cancelled,{}};
    settings.remove("Credential/Password");settings.remove("Credential/TOTPSecret");settings.sync();
    if (settings.status()==QSettings::NoError) return {Status::Success,{}};
    if (password.isValid()) settings.setValue("Credential/Password",password);
    if (totp.isValid()) settings.setValue("Credential/TOTPSecret",totp);
    settings.sync();
    return {Status::Failed,{}};
}
}

bool ProfileCredentials::hasLegacyCredentials(const QSettings &settings) {
    for (const auto &key:{"Credential/Password","Credential/TOTPSecret"}) {
        const auto value=settings.value(key);
        if (!value.isValid()) continue;
        if (value.metaType().id()==QMetaType::QString) {if (!value.toString().isEmpty()) return true;}
        else if (value.metaType().id()==QMetaType::QByteArray) {if (!value.toByteArray().isEmpty()) return true;}
        else return true;
    }
    return false;
}
QString ProfileCredentials::ensureScope(QSettings &settings) {
    if (settings.status()!=QSettings::NoError) return {};
    if (settings.contains(ScopeSetting)) {
        const auto scope=settings.value(ScopeSetting).toString();
        return validScope(scope) ? scope : QString();
    }
    const auto scope=QUuid::createUuid().toString(QUuid::WithoutBraces);
    settings.setValue(ScopeSetting,scope);settings.sync();
    return settings.status()==QSettings::NoError ? scope : QString();
}
QString ProfileCredentials::key(const QString &scope,const ConnectionProfile &p) {
    return profileKey(scope,p,"credentials-v1");
}
QString ProfileCredentials::authenticationCacheKey(const QString &scope,const ConnectionProfile &p) {
    if (p.credentials.username.isEmpty() && (p.endpoint.authType!="smsCheckCode" || p.endpoint.phone.isEmpty())) return {};
    return profileKey(scope,p,"authentication-cache-v1");
}
QString ProfileCredentials::legacyCacheKey(const QString &scope) {
    return validScope(scope) ? digest({"legacy-cache-v1",scope}) : QString();
}
CredentialResult ProfileCredentials::writeVerified(const QString &key,const QByteArray &value) {
    if (!CredentialStore::validKey(key)) return {Status::InvalidArgument,{}};
    if (value.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    const auto written=store.write(key,value);
    if (!written.succeeded()) return written;
    const auto verified=store.read(key);
    if (verified.status==Status::NotFound) return {Status::Failed,{}};
    if (!verified.succeeded()) return verified;
    if (verified.value!=value) return {Status::Failed,{}};
    return {Status::Success,{}};
}
CredentialResult ProfileCredentials::load(const QString &scope,const ConnectionProfile &p,ConnectionCredentials &credentials) {
    credentials={};
    const auto id=key(scope,p);
    if (id.isEmpty()) return {Status::InvalidArgument,{}};
    auto result=store.read(id);
    if (!result.succeeded()) {result.value.clear();return result;}
    if (result.value.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    if (!decode(result.value,credentials)) return {Status::InvalidArgument,{}};
    credentials.username=p.credentials.username;
    return {Status::Success,{}};
}
CredentialResult ProfileCredentials::save(const QString &scope,const ConnectionProfile &p) {
    if (p.credentials.username.isEmpty() && p.endpoint.phone.isEmpty()) return {Status::InvalidArgument,{}};
    if (p.credentials.password.isEmpty() && p.credentials.totpSecret.isEmpty()) return {Status::InvalidArgument,{}};
    return writeVerified(key(scope,p),encode(p.credentials));
}
CredentialResult ProfileCredentials::loadAuthenticationCache(const QString &scope,const ConnectionProfile &p,AuthenticationCache &cache) {
    cache={};
    const auto id=authenticationCacheKey(scope,p);
    if (id.isEmpty()) return {Status::InvalidArgument,{}};
    auto result=store.read(id);
    if (!result.succeeded()) {result.value.clear();return result;}
    if (result.value.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    const auto document=QJsonDocument::fromJson(result.value);
    if (!document.isObject()) return {Status::InvalidArgument,{}};
    const auto object=document.object();
    if (object.value("version").isDouble() && object.value("version").toDouble()>1) return {Status::Conflict,{}};
    if (object.size()!=4 || object.value("version")!=QJsonValue(1) || object.value("binding")!=id
        || !object.value("account").isString() || !p.matchesCacheAccount(object.value("account").toString()) || !object.value("data").isString()) return {Status::InvalidArgument,{}};
    const auto decoded=QByteArray::fromBase64Encoding(object.value("data").toString().toLatin1(),QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.isEmpty()) return {Status::InvalidArgument,{}};
    cache={object.value("account").toString(),decoded.decoded};
    return {Status::Success,{}};
}
CredentialResult ProfileCredentials::saveAuthenticationCache(const QString &scope,const ConnectionProfile &p,const AuthenticationCache &cache) {
    const auto id=authenticationCacheKey(scope,p);
    if (id.isEmpty() || !p.matchesCacheAccount(cache.account) || cache.data.isEmpty()) return {Status::InvalidArgument,{}};
    if (cache.data.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    const auto encoded=QJsonDocument(QJsonObject{{"version",1},{"binding",id},{"account",cache.account},{"data",QString::fromLatin1(cache.data.toBase64())}}).toJson(QJsonDocument::Compact);
    return writeVerified(id,encoded);
}
CredentialResult ProfileCredentials::clearAuthenticationCache(const QString &scope,const ConnectionProfile &p) {
    return removeVerified(authenticationCacheKey(scope,p));
}
CredentialResult ProfileCredentials::removeVerified(const QString &id) {
    if (!CredentialStore::validKey(id)) return {Status::InvalidArgument,{}};
    auto result=store.remove(id);
    if (!result.succeeded() && result.status!=Status::NotFound) return result;
    result=store.read(id);
    if (result.status==Status::NotFound) return {Status::Success,{}};
    if (result.succeeded()) return {Status::Failed,{}};
    result.value.clear();return result;
}
CredentialResult ProfileCredentials::preserveVerified(const QString &id,const QByteArray &value) {
    if (!CredentialStore::validKey(id)) return {Status::InvalidArgument,{}};
    if (value.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    const auto existing=store.read(id);
    if (existing.status==Status::NotFound) return writeVerified(id,value);
    if (!existing.succeeded()) return existing;
    return {existing.value==value ? Status::Success : Status::Conflict,{}};
}
CredentialResult ProfileCredentials::clear(QSettings &settings,const QString &scope,const ConnectionProfile &p) {
    const auto password=settings.value("Credential/Password"),totp=settings.value("Credential/TOTPSecret");
    if (settings.status()!=QSettings::NoError) return {Status::Failed,{}};
    if (hasLegacyCredentials(settings) && settings.value("Common/ConfigVersion").toInt()>ApplicationConstants::ConfigVersion) return {Status::InvalidArgument,{}};
    if (settings.value("Credential/Username").toString()!=p.credentials.username) return {Status::Cancelled,{}};
    const auto id=key(scope,p);
    if (!id.isEmpty()) {
        const auto removed=removeVerified(id);if (!removed.succeeded()) return removed;
    }
    const auto removed=removeVerified(archiveKey(scope,p,settings));
    if (!removed.succeeded()) return removed;
    return eraseLegacy(settings,password,totp,p.credentials.username);
}
CredentialResult ProfileCredentials::migrate(QSettings &settings,const QString &scope,const ConnectionProfile &p) {
    const auto password=settings.value("Credential/Password"),totp=settings.value("Credential/TOTPSecret");
    if (settings.status()!=QSettings::NoError) return {Status::Failed,{}};
    if (hasLegacyCredentials(settings) && settings.value("Common/ConfigVersion").toInt()>ApplicationConstants::ConfigVersion) return {Status::InvalidArgument,{}};
    for (const auto &value:{password,totp})
        if (value.isValid() && value.metaType().id()!=QMetaType::QString && value.metaType().id()!=QMetaType::QByteArray) return {Status::InvalidArgument,{}};
    const auto decoded=QByteArray::fromBase64Encoding(password.toByteArray(),QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded) return {Status::InvalidArgument,{}};
    ConnectionCredentials legacy{settings.value("Credential/Username").toString(),QString::fromUtf8(decoded.decoded),totp.toString()};
    if (legacy.password.toUtf8()!=decoded.decoded || legacy.username!=p.credentials.username) return {Status::InvalidArgument,{}};
    if (!legacy.password.isEmpty() || !legacy.totpSecret.isEmpty()) {
        if (key(scope,p).isEmpty() || (legacy.username.isEmpty() && p.endpoint.phone.isEmpty())) {
            auto archive=QJsonDocument::fromJson(encode(legacy)).object();archive.insert("username",legacy.username);
            const auto sealed=preserveVerified(archiveKey(scope,p,settings),QJsonDocument(archive).toJson(QJsonDocument::Compact));
            if (!sealed.succeeded()) return sealed;
        } else {
            ConnectionCredentials existing;
            const auto found=load(scope,p,existing);
            if (found.succeeded()) {
                // A stale INI must not overwrite a newer secure value.
                if ((!legacy.password.isEmpty() && existing.password!=legacy.password)
                    || (!legacy.totpSecret.isEmpty() && existing.totpSecret!=legacy.totpSecret)) return {Status::Conflict,{}};
            } else if (found.status==Status::NotFound) {
                auto migrated=p;migrated.credentials=legacy;
                const auto saved=save(scope,migrated);
                if (!saved.succeeded()) return saved;
            } else return found;
        }
    }
    return eraseLegacy(settings,password,totp,legacy.username);
}
CredentialResult ProfileCredentials::quarantine(const QString &path,const QString &scope) {
    const auto id=legacyCacheKey(scope);
    if (id.isEmpty()) return {Status::InvalidArgument,{}};
    const QFileInfo info(path);
    if (info.isSymLink()) return {Status::InvalidArgument,{}};
    if (!info.exists()) return {Status::NotFound,{}};
    if (!info.isFile()) return {Status::InvalidArgument,{}};
    QFile source(path);
    if (!source.open(QIODevice::ReadOnly)) return {Status::PermissionDenied,{}};
    if (source.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    const auto bytes=source.read(CredentialStore::MaxBytes+1);
    if (source.error()!=QFileDevice::NoError) return {Status::Failed,{}};
    if (bytes.size()>CredentialStore::MaxBytes) return {Status::Limit,{}};
    source.close();
    const auto saved=preserveVerified(id,bytes);
    if (!saved.succeeded()) return saved;
    if (QFileInfo(path).isSymLink() || !source.open(QIODevice::ReadOnly)) return {Status::Failed,{}};
    const auto current=source.read(CredentialStore::MaxBytes+1);
    if (source.error()!=QFileDevice::NoError || current!=bytes) return {Status::Cancelled,{}};
    source.close();
    return {source.remove() ? Status::Success : Status::Failed,{}};
}
