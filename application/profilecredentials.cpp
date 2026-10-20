#include "profilecredentials.h"
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
    if (!validScope(scope) || p.endpoint.server.isEmpty() || p.endpoint.port<1 || p.endpoint.port>65535 || p.endpoint.authType.isEmpty()) return {};
    return digest({"credentials-v1",scope,p.endpoint.server.toLower(),p.endpoint.port,p.endpoint.authType,
        p.endpoint.loginDomain,p.endpoint.authId,p.endpoint.authSubType,p.endpoint.phone,p.credentials.username});
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
    if (p.credentials.username.isEmpty() && p.endpoint.phone.isEmpty() && (!p.credentials.password.isEmpty() || !p.credentials.totpSecret.isEmpty())) return {Status::InvalidArgument,{}};
    return writeVerified(key(scope,p),encode(p.credentials));
}
CredentialResult ProfileCredentials::remove(const QString &scope,const ConnectionProfile &p) {
    const auto id=key(scope,p);
    if (id.isEmpty()) return {Status::InvalidArgument,{}};
    auto result=store.remove(id);
    if (!result.succeeded() && result.status!=Status::NotFound) return result;
    result=store.read(id);
    if (result.status==Status::NotFound) return {Status::Success,{}};
    if (result.succeeded()) return {Status::Failed,{}};
    result.value.clear();return result;
}
CredentialResult ProfileCredentials::migrate(QSettings &settings,const QString &scope,const ConnectionProfile &p) {
    const auto password=settings.value("Credential/Password"),totp=settings.value("Credential/TOTPSecret");
    if (settings.status()!=QSettings::NoError) return {Status::Failed,{}};
    const auto decoded=QByteArray::fromBase64Encoding(password.toByteArray(),QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded) return {Status::InvalidArgument,{}};
    ConnectionCredentials legacy{settings.value("Credential/Username").toString(),QString::fromUtf8(decoded.decoded),totp.toString()};
    if (legacy.password.toUtf8()!=decoded.decoded || legacy.username!=p.credentials.username) return {Status::InvalidArgument,{}};
    if (!legacy.password.isEmpty() || !legacy.totpSecret.isEmpty()) {
        ConnectionCredentials existing;
        const auto found=load(scope,p,existing);
        if (found.succeeded()) {
            // A stale INI must not overwrite a newer secure value.
            if ((!legacy.password.isEmpty() && existing.password!=legacy.password)
                || (!legacy.totpSecret.isEmpty() && existing.totpSecret!=legacy.totpSecret)) return {Status::Failed,{}};
        } else if (found.status==Status::NotFound) {
            auto migrated=p;migrated.credentials=legacy;
            const auto saved=save(scope,migrated);
            if (!saved.succeeded()) return saved;
        } else return found;
    }
    if (settings.value("Credential/Password")!=password || settings.value("Credential/TOTPSecret")!=totp
        || settings.value("Credential/Username").toString()!=legacy.username) return {Status::Cancelled,{}};
    settings.remove("Credential/Password");settings.remove("Credential/TOTPSecret");settings.sync();
    if (settings.status()==QSettings::NoError) return {Status::Success,{}};
    if (password.isValid()) settings.setValue("Credential/Password",password);
    if (totp.isValid()) settings.setValue("Credential/TOTPSecret",totp);
    settings.sync();
    return {Status::Failed,{}};
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
    const auto existing=store.read(id);
    if (existing.status==Status::NotFound) {
        const auto saved=writeVerified(id,bytes);
        if (!saved.succeeded()) return saved;
    } else if (!existing.succeeded()) return existing;
    else if (existing.value!=bytes) return {Status::Failed,{}};
    if (QFileInfo(path).isSymLink() || !source.open(QIODevice::ReadOnly)) return {Status::Failed,{}};
    const auto current=source.read(CredentialStore::MaxBytes+1);
    if (source.error()!=QFileDevice::NoError || current!=bytes) return {Status::Cancelled,{}};
    source.close();
    return {source.remove() ? Status::Success : Status::Failed,{}};
}
