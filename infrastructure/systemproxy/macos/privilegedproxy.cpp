#include "privilegedproxy.h"
#include <fcntl.h>
#include <unistd.h>

namespace {
// A single system-wide journal outlives both the app and the kernel boot.
const QUuid JournalOwner(QStringLiteral("e9511924-9402-4f1e-bc3c-30a7e15fe153"));
}

MacPrivilegedProxy::MacPrivilegedProxy()
    : native(MacProxyApi{[](AuthorizationRef *) {
        return SCPreferencesCreate(nullptr,CFSTR("JustConnect"),nullptr);
    }},[this](const QJsonObject &snapshot) {
        if (snapshot.isEmpty()) return journal.remove();
        if (snapshot["machine"].toString().isEmpty())
            return PlatformOperationResult{PlatformOperationResult::Status::Failed,"Cannot serialize browser proxy ownership."};
        return journal.store({{"owner",JournalOwner.toString(QUuid::WithoutBraces)},{"snapshot",snapshot}});
    })
{
}

PlatformOperationResult MacPrivilegedProxy::open(int bootDirectory)
{
    const int parent = ::openat(bootDirectory,"..",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (parent < 0) return {PlatformOperationResult::Status::Failed,"Cannot open the privileged network storage."};
    const int directory = openPrivateNetworkDirectory(parent,"browser-proxy");
    ::close(parent);
    if (directory < 0) return {PlatformOperationResult::Status::Failed,"Cannot open privileged browser proxy storage."};
    const auto result = journal.open(directory,JournalOwner);
    ::close(directory);
    return result;
}

PlatformOperationResult MacPrivilegedProxy::restore()
{
    if (clean) return {};
    if (!native.recoverySnapshot().isEmpty()) {
        const auto result = native.clear();
        clean=result.succeeded();
        return result;
    }
    QJsonObject record;
    const auto result = journal.load(record,true);
    if (!result.succeeded()) return result;
    if (record.isEmpty()) { clean=true; return {}; }
    if (record.size()!=2 || !record["snapshot"].isObject())
        return {PlatformOperationResult::Status::Failed,"Invalid privileged browser proxy ownership.",true};
    const auto restored=native.recover(record["snapshot"].toObject());
    clean=restored.succeeded();
    return restored;
}

PlatformOperationResult MacPrivilegedProxy::apply(const SystemProxyConfig &config)
{
    const auto result=native.apply(config);
    if (result.succeeded() || result.mayHaveChanged) clean=false;
    return result;
}
