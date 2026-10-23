#include "persistentproxy.h"
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QSysInfo>
#include <QUuid>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
bool validOwner(const QString &owner) {
    const QUuid id(owner);return !id.isNull() && id.toString(QUuid::WithoutBraces)==owner;
}
QString machine() {return QString::fromLatin1(QSysInfo::machineUniqueId().toHex());}
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
    : journal(credentials,key),
      completion(credentials,QString::fromLatin1(QCryptographicHash::hash(
          "com.github.wtalioy.JustConnect/system-proxy-completion/v1/"+key.toUtf8(),QCryptographicHash::Sha256).toHex())),
      native(std::move(api),[this](const QJsonObject &record) {
        if (!record.isEmpty() && record["machine"].toString().isEmpty())
            return Result{Status::Unsupported,"Machine identity is unavailable for proxy recovery"};
        const auto stored=owner.isEmpty()?record:QJsonObject{{"scope_version",1},{"scope",owner},{"native",record}};
        const auto result=journal.checkpoint(record.isEmpty()?QByteArray{}:QJsonDocument(stored).toJson(QJsonDocument::Compact));
        if (!result.succeeded()) return failure(result.status);
        // Startup restoration must not publish completion for the caller's upcoming operation.
        return record.isEmpty() && (resuming || (initialized && !recovering))?complete():Result{};
    }) {}

PlatformOperationResult PersistentProxyBackend::beginRecovery(const QString &scope, bool resume) {
    if(owner.isEmpty())return SystemProxyBackend::beginRecovery(scope,resume);
    if(!validOwner(scope))return {Status::Failed,"Invalid proxy recovery owner"};
    if(rejected)return *rejected;
    if((resume && initialized) || (confirmed && owner==scope))
        return {Status::Failed,"Completed or initialized proxy recovery owner cannot be reused"};
    if((resuming && !resume) || (owner!=scope && (recovering || !native.recoverySnapshot().isEmpty())))
        return {Status::Failed,"Existing proxy recovery owner must be restored first",true};
    if(owner!=scope)confirmed=false;
    owner=scope;resuming=resume;return {};
}

PlatformOperationResult PersistentProxyBackend::configureRecovery(const QString &scope, bool resume) {
    if(!validOwner(scope) || initialized || !owner.isEmpty())return {Status::Failed,"Invalid initial proxy recovery owner"};
    owner=scope;resuming=resume;return {};
}

PlatformOperationResult PersistentProxyBackend::loadCompletion() {
    if(completionLoaded)return {};
    const auto saved=completion.load();
    if(saved.status==CredentialStatus::NotFound){completionLoaded=true;return {};}
    if(!saved.succeeded())return failure(saved.status);
    const auto document=QJsonDocument::fromJson(saved.value);const auto value=document.object();
    if(!document.isObject() || document.toJson(QJsonDocument::Compact)!=saved.value || value.size()!=3
        || value["version"]!=1 || !validOwner(value["scope"].toString())
        || machine().isEmpty() || value["machine"]!=machine()) {
        rejected=Result{Status::Failed,"Invalid or foreign proxy completion proof; original data retained"};return *rejected;
    }
    confirmation=value;completionLoaded=true;return {};
}

PlatformOperationResult PersistentProxyBackend::complete() {
    if(owner.isEmpty())return {};
    if(machine().isEmpty())return {Status::Unsupported,"Machine identity is unavailable for proxy completion"};
    if(auto result=loadCompletion();!result.succeeded())return result;
    const QJsonObject value{{"version",1},{"scope",owner},{"machine",machine()}};
    const auto saved=completion.checkpoint(QJsonDocument(value).toJson(QJsonDocument::Compact));
    if(!saved.succeeded())return failure(saved.status);
    confirmation=value;confirmed=true;resuming=false;return {};
}

PlatformOperationResult PersistentProxyBackend::finishUnowned() {
    if(owner.isEmpty() || confirmed)return {};
    const auto removed=journal.checkpoint({});
    if(!removed.succeeded())return failure(removed.status);
    return complete();
}

PlatformOperationResult PersistentProxyBackend::recover() {
    if (rejected) return *rejected;
    if (initialized) {
        if (!recovering) return {};
        const auto result=native.clear();recovering=!result.succeeded();return result;
    }
    const auto saved=journal.load();
    if(resuming) {
        if(auto result=loadCompletion();!result.succeeded())return result;
        if(confirmation["scope"]==owner) {
            // Completion is published only after confirmed snapshot removal; any present record is a later owner.
            if(saved.succeeded())rejected=Result{Status::Failed,"Later proxy recovery data retained"};
            else if(saved.status!=CredentialStatus::NotFound)return failure(saved.status);
            initialized=confirmed=true;resuming=false;return {};
        }
    }
    if (saved.status==CredentialStatus::NotFound) {
        if(resuming) {rejected=Result{Status::Failed,"Original proxy recovery data and completion proof are unavailable"};return *rejected;}
        initialized=true;return {};
    }
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
    auto record=document.object();
    if(record.contains("scope_version")) {
        if(record.size()!=3 || record["scope_version"]!=1 || !validOwner(record["scope"].toString()) || !record["native"].isObject()) {
            rejected=Result{Status::Failed,"Invalid scoped proxy recovery record; original data retained"};return *rejected;
        }
        if(resuming && record["scope"]!=owner) {
            rejected=Result{Status::Failed,"Different proxy recovery owner; original data retained"};return *rejected;
        }
        if(owner.isEmpty())owner=record["scope"].toString();
        record=record["native"].toObject();
    } else if(resuming) {
        rejected=Result{Status::Failed,"Previous proxy recovery owner cannot be confirmed"};return *rejected;
    }
    auto result=native.recover(record);
    initialized=result.succeeded() || !native.recoverySnapshot().isEmpty();
    recovering=initialized && !result.succeeded();
    if (!initialized) rejected=result;
    return result;
}

SystemProxyCheck PersistentProxyBackend::check(const SystemProxyConfig &config) {
    if (auto result=recover();!result.succeeded()) return {result};
    const auto result=native.check(config);
    if(native.recoverySnapshot().isEmpty()) {
        if(auto completed=finishUnowned();!completed.succeeded()) {completed.mayHaveChanged=false;return {completed};}
    }
    return result;
}
PlatformOperationResult PersistentProxyBackend::apply(const SystemProxyConfig &config) {
    if(confirmed)return {Status::Failed,"A new proxy application requires a fresh recovery owner"};
    if (auto result=recover();!result.succeeded()) return result;
    return native.apply(config);
}
PlatformOperationResult PersistentProxyBackend::clear() {
    if(confirmed)return {};
    if (auto result=recover();!result.succeeded()) return result;
    if(confirmed)return {};
    const auto result=native.clear();
    return result.succeeded()?finishUnowned():result;
}
