#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyvalidation.h"
#include "application/credentialstore.h"
#include <QScopeGuard>
#include <QSysInfo>
#include <QUuid>
#include <QSet>
#include <unistd.h>
#include <vector>

SCPreferencesRef createMacProxyPreferences(AuthorizationRef *authorization) {
    if (AuthorizationCreate(nullptr, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, authorization) != errAuthorizationSuccess) return nullptr;
    return SCPreferencesCreateWithAuthorization(nullptr, CFSTR("JustConnect"), nullptr, *authorization);
}

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result error(const QString &operation, bool changed = false) {
    const auto code = SCError();
    const auto status = code == errAuthorizationCanceled ? Status::Cancelled
        : code == kSCStatusAccessError || code == errAuthorizationDenied ? Status::PermissionDenied
        : code == kSCStatusNoConfigFile ? Status::Unsupported : Status::Failed;
    return {status, operation + ": SystemConfiguration error " + QString::number(code), changed};
}
CFStringRef path(SCNetworkServiceRef service) {
    return CFStringCreateWithFormat(nullptr, nullptr, CFSTR("/%@/%@/%@"), kSCPrefNetworkServices, SCNetworkServiceGetServiceID(service), kSCEntNetProxies);
}
Result read(SCPreferencesRef prefs, CFStringRef path, CFDictionaryRef &value) {
    auto parent = CFStringCreateWithSubstring(nullptr, path, CFRangeMake(0, CFStringGetLength(path) - CFStringGetLength(kSCEntNetProxies) - 1));
    auto service = SCPreferencesPathGetValue(prefs, parent); CFRelease(parent);
    if (!service) return {Status::Failed, "Network service no longer exists"};
    auto raw = CFDictionaryGetValue(service, kSCEntNetProxies);
    if (raw && CFGetTypeID(raw) != CFDictionaryGetTypeID()) return {Status::Failed, "Invalid native proxy configuration"};
    value = static_cast<CFDictionaryRef>(raw); return {};
}
bool write(const MacProxyApi &api, SCPreferencesRef prefs, CFStringRef path, CFDictionaryRef value) {
    if (value) return api.set(prefs, path, value);
    return !SCPreferencesPathGetValue(prefs, path) || api.remove(prefs, path);
}
CFMutableDictionaryRef dictionary(CFDictionaryRef original = nullptr) {
    return original ? CFDictionaryCreateMutableCopy(nullptr, 0, original)
        : CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}
void number(CFMutableDictionaryRef values, CFStringRef key, int value) {
    auto native = CFNumberCreate(nullptr, kCFNumberIntType, &value);
    CFDictionarySetValue(values, key, native); CFRelease(native);
}
bool same(CFDictionaryRef a, CFDictionaryRef b, CFStringRef key) {
    auto left = a ? CFDictionaryGetValue(a, key) : nullptr;
    auto right = b ? CFDictionaryGetValue(b, key) : nullptr;
    return left == right || (left && right && CFEqual(left, right));
}
bool enabled(CFDictionaryRef values, CFStringRef key) {
    if (!values) return false;
    auto value = CFDictionaryGetValue(values, key); int flag = 0;
    return value && CFGetTypeID(value) == CFNumberGetTypeID() && CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberIntType, &flag) && flag != 0;
}
const CFStringRef modes[]{kSCPropNetProxiesProxyAutoConfigEnable, kSCPropNetProxiesProxyAutoDiscoveryEnable};
struct Endpoint { CFStringRef enabled, host, port, authenticated, username, password; };
const Endpoint endpoints[]{
    {kSCPropNetProxiesHTTPEnable,kSCPropNetProxiesHTTPProxy,kSCPropNetProxiesHTTPPort,CFSTR("HTTPProxyAuthenticated"),CFSTR("HTTPProxyUsername"),CFSTR("HTTPProxyPassword")},
    {kSCPropNetProxiesHTTPSEnable,kSCPropNetProxiesHTTPSProxy,kSCPropNetProxiesHTTPSPort,CFSTR("HTTPSProxyAuthenticated"),CFSTR("HTTPSProxyUsername"),CFSTR("HTTPSProxyPassword")},
    {kSCPropNetProxiesSOCKSEnable,kSCPropNetProxiesSOCKSProxy,kSCPropNetProxiesSOCKSPort,CFSTR("SOCKSProxyAuthenticated"),CFSTR("SOCKSProxyUsername"),CFSTR("SOCKSProxyPassword")}
};
CFMutableDictionaryRef requested(CFDictionaryRef before, const SystemProxyConfig &config) {
    auto values = dictionary(before);
    for (int i = 0; i < 3; ++i) {
        const auto &endpoint = endpoints[i];
        number(values, endpoint.enabled, 1); number(values, endpoint.port, i == 2 ? config.socksPort : config.httpPort);
        CFDictionarySetValue(values, endpoint.host, CFSTR("127.0.0.1"));
        // Keep old authentication material in the snapshot, never on the temporary local endpoint.
        number(values, endpoint.authenticated, 0);
        CFDictionaryRemoveValue(values, endpoint.username); CFDictionaryRemoveValue(values, endpoint.password);
    }
    for (const auto key : modes) number(values, key, 0);
    auto bypass = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
    for (const auto &domain : ProxyValidation::bypass(config.bypass)) {
        auto text = CFStringCreateWithCharacters(nullptr, reinterpret_cast<const UniChar *>(domain.utf16()), domain.size());
        CFArrayAppendValue(bypass, text); CFRelease(text);
    }
    CFDictionarySetValue(values, kSCPropNetProxiesExceptionsList, bypass); CFRelease(bypass);
    return values;
}
bool matches(CFDictionaryRef actual, CFDictionaryRef expected) {
    if (!actual) return false;
    for (const auto &endpoint : endpoints)
        for (const auto key : {endpoint.enabled,endpoint.host,endpoint.port,endpoint.authenticated,endpoint.username,endpoint.password})
            if (!same(actual, expected, key)) return false;
    for (const auto key : modes) if (!same(actual, expected, key)) return false;
    return same(actual, expected, kSCPropNetProxiesExceptionsList);
}
}

struct PlatformSystemProxyBackend::Snapshot {
    struct Service { CFStringRef path; CFDictionaryRef before, installed; };
    AuthorizationRef authorization = nullptr;
    SCPreferencesRef preferences = nullptr;
    std::vector<Service> services;
    bool restorationCommitted = false;
    SystemProxyConfig config;
    QUuid owner = QUuid::createUuid();
    ~Snapshot() {
        for (const auto &service : services) { CFRelease(service.path); if (service.before) CFRelease(service.before); CFRelease(service.installed); }
        if (preferences) CFRelease(preferences);
        if (authorization) AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    }
};

QJsonObject PlatformSystemProxyBackend::recoverySnapshot() const {
    if (!snapshot) return {};
    QJsonArray services;
    for (const auto &service:snapshot->services) {
        QJsonValue before(QJsonValue::Null);
        if (service.before) {
            const auto data=CFPropertyListCreateData(nullptr,service.before,kCFPropertyListBinaryFormat_v1_0,0,nullptr);
            if (!data) return {{"serialization_error",true}};
            before=QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),CFDataGetLength(data)).toBase64());CFRelease(data);
        }
        services.append(QJsonObject{{"id",QString::fromCFString(service.path).section('/',2,2)},{"before",before}});
    }
    return {{"schema_version",1},{"platform","macos"},{"machine",QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"uid",qint64(geteuid())},{"owner",snapshot->owner.toString(QUuid::WithoutBraces)},
        {"config",QJsonObject{{"http_port",snapshot->config.httpPort},{"socks_port",snapshot->config.socksPort},{"bypass",snapshot->config.bypass}}},
        {"services",services},{"restoration_committed",snapshot->restorationCommitted}};
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed,"Existing system proxy ownership must be restored first",true};
    const auto invalid=[] { return Result{Status::Failed,"Invalid or foreign macOS proxy recovery record"}; };
    const auto bytes=QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine=QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText=record["owner"].toString();const QUuid owner(ownerText);
    if (bytes.size()>CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object()!=record || record.size()!=8
        || record["schema_version"]!=1 || record["platform"]!="macos" || machine.isEmpty() || record["machine"]!=machine
        || record["uid"].toInteger(-1)!=qint64(geteuid()) || owner.isNull() || owner.toString(QUuid::WithoutBraces)!=ownerText
        || !record["config"].isObject() || !record["services"].isArray() || !record["restoration_committed"].isBool()) return invalid();
    const auto config=record["config"].toObject();
    const auto http=config["http_port"].toInteger(-1),socks=config["socks_port"].toInteger(-1);
    if (config.size()!=3 || http<1 || http>65535 || socks<1 || socks>65535 || !config["bypass"].isString()) return invalid();
    auto pending=std::make_shared<Snapshot>();pending->owner=owner;pending->config={int(http),int(socks),config["bypass"].toString()};
    if (!ProxyValidation::config(pending->config).succeeded()) return invalid();
    pending->restorationCommitted=record["restoration_committed"].toBool();QSet<QString> ids;
    for (const auto &value:record["services"].toArray()) {
        if (!value.isObject()) return invalid();
        const auto service=value.toObject();const auto id=service["id"].toString();
        if (service.size()!=2 || id.isEmpty() || id=="." || id==".." || id.contains('/') || id.contains(QChar(0)) || ids.contains(id)) return invalid();
        ids.insert(id);CFDictionaryRef before=nullptr;
        if (!service["before"].isNull()) {
            if (!service["before"].isString()) return invalid();
            const auto encoded=service["before"].toString().toLatin1();const auto data=QByteArray::fromBase64(encoded);
            if (data.toBase64()!=encoded || !data.startsWith("bplist00")) return invalid();
            const auto native=CFDataCreate(nullptr,reinterpret_cast<const UInt8 *>(data.constData()),data.size());
            if (!native) return invalid();
            const auto decoded=CFPropertyListCreateWithData(nullptr,native,kCFPropertyListImmutable,nullptr,nullptr);CFRelease(native);
            if (!decoded) return invalid();
            if (CFGetTypeID(decoded)!=CFDictionaryGetTypeID()) {CFRelease(decoded);return invalid();}
            before=static_cast<CFDictionaryRef>(decoded);
        }
        const auto location=QString("/NetworkServices/")+id+"/Proxies";
        auto path=CFStringCreateWithCharacters(nullptr,reinterpret_cast<const UniChar *>(location.utf16()),location.size());
        pending->services.push_back({path,before,requested(before,pending->config)});
    }
    if (pending->services.empty()) return invalid();
    pending->preferences=api.open(&pending->authorization);
    if (!pending->preferences) return error("Open proxy recovery preferences");
    snapshot=pending;return clear();
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    Snapshot view; view.preferences = api.open(&view.authorization);
    if (!view.preferences) return {error("Open proxy preferences")};
    auto all = SCNetworkServiceCopyAll(view.preferences);
    if (!all) return {error("Read network services")};
    const auto release = qScopeGuard([&] { CFRelease(all); });
    bool active = false, conflict = false, supported = false;
    for (CFIndex i = 0; i < CFArrayGetCount(all); ++i) {
        auto service = static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(all, i));
        if (!SCNetworkServiceGetEnabled(service)) continue;
        auto location = path(service); const auto releasePath = qScopeGuard([&] { CFRelease(location); });
        CFDictionaryRef current = nullptr;
        if (auto result = read(view.preferences, location, current); !result.succeeded()) return {result};
        const auto desired = requested(current, config);
        const auto releaseDesired = qScopeGuard([&] { CFRelease(desired); });
        supported = true;
        for (const auto &endpoint : endpoints) if (enabled(current, endpoint.enabled)) {
            active = true;
            conflict |= !same(current, desired, endpoint.host) || !same(current, desired, endpoint.port) || enabled(current, endpoint.authenticated);
        }
        for (const auto key : modes) conflict |= enabled(current, key);
    }
    if (!supported) return {{Status::Unsupported, "No enabled network services"}};
    return {{}, conflict, active};
}

PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return valid;
    if (snapshot) return {Status::Failed, "Restore the current proxy settings before applying another configuration", true};
    auto pending = std::make_shared<Snapshot>(); pending->preferences = api.open(&pending->authorization);
    pending->config = config;
    if (!pending->preferences) return error("Open proxy preferences");
    auto prefs = pending->preferences;
    SCPreferencesSynchronize(prefs);
    if (!SCPreferencesLock(prefs, false)) return error("Lock proxy preferences");
    bool locked = true;
    const auto unlock = qScopeGuard([&] { if (locked) SCPreferencesUnlock(prefs); });
    auto all = SCNetworkServiceCopyAll(prefs);
    if (!all) return error("Read network services");
    const auto release = qScopeGuard([&] { CFRelease(all); });
    for (CFIndex i = 0; i < CFArrayGetCount(all); ++i) {
        auto service = static_cast<SCNetworkServiceRef>(CFArrayGetValueAtIndex(all, i));
        if (!SCNetworkServiceGetEnabled(service)) continue;
        auto location = path(service); CFDictionaryRef before = nullptr;
        const auto result = read(prefs, location, before);
        if (!result.succeeded()) { CFRelease(location); return result; }
        pending->services.push_back({location, before ? static_cast<CFDictionaryRef>(CFRetain(before)) : nullptr, requested(before, config)});
    }
    if (pending->services.empty()) return {Status::Unsupported, "No enabled network services"};
    // All edits remain in this locked preferences session until the single commit.
    for (const auto &service : pending->services)
        if (!write(api, prefs, service.path, service.installed)) return error("Set proxy preferences");
    snapshot = pending;
    auto result = Result{};
    if (!api.commit(prefs)) result = error("Commit proxy preferences", true);
    else if (!api.apply(prefs)) result = error("Apply proxy preferences", true);
    SCPreferencesUnlock(prefs); locked = false;
    if (result.succeeded()) {
        SCPreferencesSynchronize(prefs);
        for (const auto &service : pending->services) {
            CFDictionaryRef actual = nullptr;
            const bool verified = read(prefs, service.path, actual).succeeded() && matches(actual, service.installed);
            if (!verified) { result = {Status::Failed, "Proxy preferences readback mismatch", true}; break; }
        }
    }
    if (!result.succeeded()) { const auto restored = clear(); result.mayHaveChanged = !restored.succeeded(); return result; }
    return {Status::Success, {}, true};
}

PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (!snapshot) return {};
    auto saved = snapshot;
    auto prefs = saved->preferences;
    SCPreferencesSynchronize(prefs);
    if (!SCPreferencesLock(prefs, false)) return error("Lock proxy preferences for restoration", true);
    const auto unlock = qScopeGuard([&] { SCPreferencesUnlock(prefs); });
    if (saved->restorationCommitted) {
        if (!api.apply(prefs)) return error("Apply restored proxy preferences", true);
        snapshot.reset();return {};
    }
    auto expected = dictionary();
    const auto releaseExpected = qScopeGuard([&] { CFRelease(expected); });
    for (const auto &service : saved->services) {
        auto parent = CFStringCreateWithSubstring(nullptr, service.path, CFRangeMake(0, CFStringGetLength(service.path) - CFStringGetLength(kSCEntNetProxies) - 1));
        const bool exists = SCPreferencesPathGetValue(prefs, parent) != nullptr; CFRelease(parent);
        if (!exists) continue;
        CFDictionaryRef current = nullptr;
        if (auto result = read(prefs, service.path, current); !result.succeeded()) { result.mayHaveChanged = true; return result; }
        auto restored = dictionary(current);
        const auto release = qScopeGuard([&] { CFRelease(restored); });
        const auto restore = [&](std::initializer_list<CFStringRef> keys) {
            for (const auto key : keys) if (!same(current, service.before, key) && !same(current, service.installed, key)) return;
            for (const auto key : keys) {
                auto value = service.before ? CFDictionaryGetValue(service.before, key) : nullptr;
                if (value) CFDictionarySetValue(restored, key, value); else CFDictionaryRemoveValue(restored, key);
            }
        };
        for (const auto &endpoint : endpoints)
            restore({endpoint.enabled,endpoint.host,endpoint.port,endpoint.authenticated,endpoint.username,endpoint.password});
        restore({kSCPropNetProxiesExceptionsList});
        bool endpointsRestored = true;
        for (const auto &endpoint : endpoints)
            for (const auto key : {endpoint.enabled,endpoint.host,endpoint.port,endpoint.authenticated,endpoint.username,endpoint.password}) endpointsRestored &= same(restored, service.before, key);
        if (endpointsRestored && same(current, service.before, kSCPropNetProxiesProxyAutoConfigURLString))
            for (const auto key : modes) restore({key});
        const auto target = !service.before && CFDictionaryGetCount(restored) == 0 ? nullptr : restored;
        if (!write(api, prefs, service.path, target)) return error("Restore proxy preferences", true);
        CFDictionarySetValue(expected, service.path, target ? static_cast<CFTypeRef>(target) : kCFNull);
    }
    if (!api.commit(prefs)) return error("Commit restored proxy preferences", true);
    SCPreferencesSynchronize(prefs);
    for (const auto &service : saved->services) {
        auto target = CFDictionaryGetValue(expected, service.path);
        if (!target) continue;
        CFDictionaryRef actual = nullptr;
        const bool verified = read(prefs, service.path, actual).succeeded() && (target == kCFNull ? actual == nullptr : actual && CFEqual(actual, target));
        if (!verified) return {Status::Failed, "Restored proxy preferences readback mismatch", true};
    }
    saved->restorationCommitted = true;
    if (!api.apply(prefs)) return error("Apply restored proxy preferences", true);
    snapshot.reset(); return {};
}
