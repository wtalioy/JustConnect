#include "infrastructure/dns/macos/dnssnapshot.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/dns/macos/propertylist.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QScopeGuard>


DnsSnapshot readMacDnsSnapshot(MacDnsRead read, PlatformCommandRunner inspect)
{
    using Status = PlatformOperationResult::Status;
    const auto store = SCDynamicStoreCreate(nullptr, CFSTR("JustConnect DNS snapshot"), nullptr, nullptr);
    if (!store) return {{Status::Failed, "Cannot open system resolver store"}, {}};
    const auto releaseStore = qScopeGuard([&] { CFRelease(store); });
    const void *pattern = CFSTR("^(State|Setup):/Network/.*/DNS$");
    const auto patterns = CFArrayCreate(nullptr, &pattern, 1, &kCFTypeArrayCallBacks);
    if (!patterns) return {{Status::Failed, "Cannot prepare system resolver query"}, {}};
    const auto releasePatterns = qScopeGuard([&] { CFRelease(patterns); });
    const auto values = read(store, nullptr, patterns);
    if (!values) return {{Status::Failed, "Cannot read system resolver store"}, {}};
    const auto releaseValues = qScopeGuard([&] { CFRelease(values); });
    const auto converted = macDnsProperties(values);
    bool valid = converted && converted->isObject();
    const auto entries = converted.value_or(QJsonValue{}).toObject();
    for (const auto &value : entries) if (!value.isObject()) valid = false;
    if (!valid) return {{Status::Failed, "Unsupported system resolver property"}, {}};
    if (QJsonDocument(entries).toJson(QJsonDocument::Compact).size() > MacDnsSnapshotBytes)
        return {{Status::Failed,"System resolver snapshot too large"},{}};
    if (!inspect) inspect = [](const QString &program,const QStringList &arguments) { return runPlatformCommand(program,arguments); };
    const auto effective = inspect(QStringLiteral("/usr/sbin/scutil"),{QStringLiteral("--dns")});
    if (!effective.result.succeeded()) return {effective.result,{}};
    const auto resolvers = parseMacDnsResolvers(effective.output);
    if (!resolvers) return {{Status::Failed,"Invalid effective system resolver configuration"},{}};
    const QJsonObject data{{"dynamic_store",entries},{"macos_resolvers",*resolvers}};
    if (QJsonDocument(data).toJson(QJsonDocument::Compact).size() > MacDnsSnapshotBytes)
        return {{Status::Failed, "System resolver snapshot too large"}, {}};
    return {{}, data};
}
