#include "persistentproxy.h"
#include <QJsonDocument>
#include <QCryptographicHash>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result failure(CredentialStatus status) {
    const auto mapped=status==CredentialStatus::Locked || status==CredentialStatus::PermissionDenied
        ? Status::PermissionDenied : status==CredentialStatus::Cancelled ? Status::Cancelled : Status::Failed;
    return {mapped,QString("Protected system proxy recovery storage is not confirmed (credential status %1)").arg(int(status)),true};
}
}

QString PersistentProxyBackend::credentialKey() {
    return QString::fromLatin1(QCryptographicHash::hash("com.github.wtalioy.JustConnect/system-proxy-recovery/v1",QCryptographicHash::Sha256).toHex());
}

#ifdef Q_OS_WIN
PersistentProxyBackend::PersistentProxyBackend(CredentialStore &credentials, QString key, WindowsProxyApi api)
#elif defined(Q_OS_MACOS)
PersistentProxyBackend::PersistentProxyBackend(CredentialStore &credentials, QString key, MacProxyApi api)
#else
PersistentProxyBackend::PersistentProxyBackend(CredentialStore &credentials, QString key, PlatformCommandRunner api)
#endif
    : journal(credentials,std::move(key)), native(std::move(api),[this](const QJsonObject &record) {
        if (!record.isEmpty() && record["machine"].toString().isEmpty())
            return Result{Status::Unsupported,"Machine identity is unavailable for proxy recovery"};
        const auto result=journal.checkpoint(record.isEmpty()?QByteArray{}:QJsonDocument(record).toJson(QJsonDocument::Compact));
        return result.succeeded()?Result{}:failure(result.status);
    }) {}

PlatformOperationResult PersistentProxyBackend::recover() {
    if (rejected) return *rejected;
    if (initialized) {
        if (!recovering) return {};
        const auto result=native.clear();recovering=!result.succeeded();return result;
    }
    const auto saved=journal.load();
    if (saved.status==CredentialStatus::NotFound) {initialized=true;return {};}
    if (!saved.succeeded()) {
        const auto result=failure(saved.status);
        if (saved.status==CredentialStatus::Failed || saved.status==CredentialStatus::Limit
            || saved.status==CredentialStatus::InvalidArgument) {
            rejected=result;rejected->mayHaveChanged=false;return *rejected;
        }
        return result;
    }
    const auto document=QJsonDocument::fromJson(saved.value);
    if (!document.isObject() || document.toJson(QJsonDocument::Compact)!=saved.value) {
        rejected=Result{Status::Failed,"Invalid protected system proxy recovery record; original data retained"};
        return *rejected;
    }
    auto result=native.recover(document.object());
    initialized=result.succeeded() || !native.recoverySnapshot().isEmpty();
    recovering=initialized && !result.succeeded();
    if (!initialized) rejected=result;
    return result;
}

SystemProxyCheck PersistentProxyBackend::check(const SystemProxyConfig &config) {
    if (auto result=recover();!result.succeeded()) return {result};
    return native.check(config);
}
PlatformOperationResult PersistentProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto result=recover();!result.succeeded()) return result;
    return native.apply(config);
}
PlatformOperationResult PersistentProxyBackend::clear() {
    if (auto result=recover();!result.succeeded()) return result;
    return native.clear();
}
