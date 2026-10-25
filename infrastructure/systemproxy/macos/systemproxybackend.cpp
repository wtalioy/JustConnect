#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/proxyvalidation.h"
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
const std::vector<std::vector<CFStringRef>> groups = [] {
    std::vector<std::vector<CFStringRef>> result;
    for (const auto &endpoint : endpoints)
        result.push_back({endpoint.enabled,endpoint.host,endpoint.port,endpoint.authenticated,endpoint.username,endpoint.password});
    result.push_back({kSCPropNetProxiesExceptionsList});
    for (auto key : modes) result.push_back({key});
    return result;
}();
constexpr unsigned EndpointFields=7, ModeFields=48, AllFields=63;
bool sameGroup(CFDictionaryRef a, CFDictionaryRef b, size_t group) {
    for (auto key : groups[group]) if (!same(a,b,key)) return false;
    return true;
}
bool matches(CFDictionaryRef actual, CFDictionaryRef expected) {
    if (!actual) return false;
    for (size_t group=0;group<groups.size();++group)
        if (!sameGroup(actual,expected,group)) return false;
    return true;
}
bool equal(CFDictionaryRef a, CFDictionaryRef b) { return a==b || (a && b && CFEqual(a,b)); }
}

struct PlatformSystemProxyBackend::Snapshot {
    struct Service {
        CFStringRef path; CFDictionaryRef before, installed;
        unsigned released=0,intent=0,written=0,uncertain=0,pendingRestore=0;
    };
    AuthorizationRef authorization = nullptr;
    SCPreferencesRef preferences = nullptr;
    std::vector<Service> services;
    bool restorationCommitted = false, dirty = false, commitAttempted = false;
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
        services.append(QJsonObject{{"id",QString::fromCFString(service.path).section('/',2,2)},{"before",before},
            {"released",qint64(service.released)},{"intent",qint64(service.intent)},{"written",qint64(service.written)},
            {"uncertain",qint64(service.uncertain)},{"pending_restore",qint64(service.pendingRestore)}});
    }
    return {{"schema_version",2},{"platform","macos"},{"machine",QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"uid",qint64(geteuid())},{"owner",snapshot->owner.toString(QUuid::WithoutBraces)},
        {"config",QJsonObject{{"http_port",snapshot->config.httpPort},{"socks_port",snapshot->config.socksPort},{"bypass",snapshot->config.bypass}}},
        {"services",services},{"restoration_committed",snapshot->restorationCommitted}};
}

PlatformOperationResult PlatformSystemProxyBackend::checkpoint(bool remove) {
    auto result=checkpointWriter ? checkpointWriter(remove ? QJsonObject{} : recoverySnapshot()) : Result{};
    if (!result.succeeded() && snapshot && snapshot->dirty) result.mayHaveChanged=true;
    return result;
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed,"Existing system proxy ownership must be restored first",true};
    const auto invalid=[] { return Result{Status::Failed,"Invalid or foreign macOS proxy recovery record"}; };
    const auto bytes=QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine=QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText=record["owner"].toString();const QUuid owner(ownerText);
    if (bytes.size()>CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object()!=record || record.size()!=8
        || record["schema_version"]!=2 || record["platform"]!="macos" || machine.isEmpty() || record["machine"]!=machine
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
        if (service.size()!=7 || id.isEmpty() || id=="." || id==".." || id.contains('/') || id.contains(QChar(0)) || ids.contains(id)) return invalid();
        Snapshot::Service entry{};
        for (const auto &field : std::initializer_list<std::pair<const char *,unsigned *>>{
                 {"released",&entry.released},{"intent",&entry.intent},{"written",&entry.written},
                 {"uncertain",&entry.uncertain},{"pending_restore",&entry.pendingRestore}}) {
            const auto value=service[field.first].toInteger(-1);
            if (value<0 || value>AllFields) return invalid();
            *field.second=unsigned(value);
        }
        if ((entry.written&~entry.intent) || (entry.uncertain&~entry.intent) || (entry.released&entry.uncertain)
            || (entry.pendingRestore&(~entry.intent|entry.released|entry.uncertain))
            || (pending->restorationCommitted && (entry.intent&~entry.released))) return invalid();
        pending->dirty|=entry.intent!=0;
        entry.uncertain|=((entry.intent&~entry.written)|entry.pendingRestore)&~entry.released;
        entry.pendingRestore=0;
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
        entry.path=path;entry.before=before;entry.installed=requested(before,pending->config);
        pending->services.push_back(entry);
    }
    if (pending->services.empty()) return invalid();
    pending->commitAttempted=true;
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
    snapshot=pending;
    if (auto result=checkpoint();!result.succeeded()) {
        if (!result.mayHaveChanged) snapshot.reset();
        return result;
    }
    for (auto &service : pending->services)
        for (size_t group=0;group<groups.size();++group)
            if (!sameGroup(service.before,service.installed,group)) service.intent|=1u<<group;
    pending->dirty=true;
    if (auto result=checkpoint();!result.succeeded()) return result;
    SCPreferencesSynchronize(prefs);
    for (const auto &service : pending->services) {
        CFDictionaryRef current=nullptr;
        if (!read(prefs,service.path,current).succeeded() || !equal(current,service.before))
            return {Status::Failed,"Proxy preferences changed while recording application intent",true};
    }
    // All edits remain in this locked preferences session until the single commit.
    auto result = Result{};
    for (const auto &service : pending->services)
        if (!write(api,prefs,service.path,service.installed)) { result=error("Set proxy preferences");break; }
    if (result.succeeded()) {
        pending->commitAttempted=true;
        if (!api.commit(prefs)) result=error("Commit proxy preferences",true);
    }
    SCPreferencesSynchronize(prefs);
    if (result.succeeded()) {
        for (auto &service : pending->services) {
            CFDictionaryRef actual = nullptr;
            const bool verified = read(prefs, service.path, actual).succeeded() && matches(actual, service.installed);
            if (!verified) { result = {Status::Failed, "Proxy preferences readback mismatch", true}; break; }
            service.written=service.intent;
        }
        if (result.succeeded()) result=checkpoint();
        if (result.succeeded() && !api.apply(prefs)) result=error("Apply proxy preferences",true);
    }
    SCPreferencesUnlock(prefs);locked=false;
    if (!result.succeeded()) { const auto restored = clear(); result.mayHaveChanged = !restored.succeeded(); return result; }
    return {Status::Success, {}, true};
}

PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (!snapshot) return {};
    auto saved = snapshot;
    if (!saved->commitAttempted) {
        // Staged edits never reached commit; a matching external value is not ours.
        for (auto &service : saved->services) {service.released=AllFields;service.uncertain=service.pendingRestore=0;}
        saved->restorationCommitted=true;
        if (auto result=checkpoint();!result.succeeded()) return result;
        if (auto result=checkpoint(true);!result.succeeded()) return result;
        snapshot.reset();return {};
    }
    auto prefs = saved->preferences;
    SCPreferencesSynchronize(prefs);
    if (!SCPreferencesLock(prefs, false)) return error("Lock proxy preferences for restoration", true);
    const auto unlock = qScopeGuard([&] { SCPreferencesUnlock(prefs); });
    if (saved->restorationCommitted) {
        if (!api.apply(prefs)) return error("Apply restored proxy preferences", true);
        if (auto result=checkpoint(true);!result.succeeded()) return result;
        snapshot.reset();return {};
    }
    for (auto &service : saved->services)
        service.pendingRestore=service.intent&~(service.released|service.uncertain);
    if (auto result=checkpoint();!result.succeeded()) return result;
    SCPreferencesSynchronize(prefs);
    auto expected=dictionary(),observed=dictionary();
    const auto releaseExpected=qScopeGuard([&] {CFRelease(expected);CFRelease(observed);});
    bool changed=false,unresolved=false;
    for (auto &service : saved->services) {
        auto parent = CFStringCreateWithSubstring(nullptr, service.path, CFRangeMake(0, CFStringGetLength(service.path) - CFStringGetLength(kSCEntNetProxies) - 1));
        const bool exists = SCPreferencesPathGetValue(prefs, parent) != nullptr; CFRelease(parent);
        if (!exists) {service.released=AllFields;service.uncertain=service.pendingRestore=0;continue;}
        CFDictionaryRef current = nullptr;
        if (auto result = read(prefs, service.path, current); !result.succeeded()) { result.mayHaveChanged = true; return result; }
        auto restored = dictionary(current);
        const auto release = qScopeGuard([&] { CFRelease(restored); });
        const auto restore = [&](size_t group, bool allowRestore=true) {
            const auto bit=1u<<group;
            if (!(service.intent&bit) || (service.released&bit)) {service.released|=bit;return;}
            bool original=sameGroup(current,service.before,group),external=false;
            for (auto key : groups[group])
                external|=!same(current,service.before,key) && !same(current,service.installed,key);
            if (original || external) {service.released|=bit;service.uncertain&=~bit;return;}
            if (service.uncertain&bit) {unresolved=true;return;}
            if (!allowRestore) {service.pendingRestore&=~bit;unresolved=true;return;}
            for (auto key : groups[group]) {
                auto value = service.before ? CFDictionaryGetValue(service.before, key) : nullptr;
                if (value) CFDictionarySetValue(restored, key, value); else CFDictionaryRemoveValue(restored, key);
            }
        };
        for (size_t group=0;group<4;++group) restore(group);
        bool endpointsRestored = true;
        for (size_t group=0;group<3;++group) endpointsRestored&=sameGroup(restored,service.before,group);
        if (endpointsRestored && same(current,service.before,kSCPropNetProxiesProxyAutoConfigURLString)) {
            restore(4);restore(5);
        } else if ((service.uncertain&EndpointFields) && same(current,service.before,kSCPropNetProxiesProxyAutoConfigURLString)) {
            restore(4,false);restore(5,false);
        } else {
            service.released|=ModeFields;service.uncertain&=~ModeFields;
        }
        service.pendingRestore&=~(service.released|service.uncertain);
        const auto target = !service.before && CFDictionaryGetCount(restored) == 0 ? nullptr : restored;
        changed|=!equal(current,target);
        CFDictionarySetValue(observed,service.path,current ? static_cast<CFTypeRef>(current) : kCFNull);
        CFDictionarySetValue(expected, service.path, target ? static_cast<CFTypeRef>(target) : kCFNull);
    }
    if (auto result=checkpoint();!result.succeeded()) return result;
    SCPreferencesSynchronize(prefs);
    for (const auto &service : saved->services) {
        const auto previous=CFDictionaryGetValue(observed,service.path);
        if (!previous) continue;
        CFDictionaryRef current=nullptr;
        if (!read(prefs,service.path,current).succeeded()
            || !equal(current,previous==kCFNull ? nullptr : static_cast<CFDictionaryRef>(previous)))
            return {Status::Failed,"Proxy preferences changed while recording restoration intent",true};
    }
    for (const auto &service : saved->services) {
        const auto value=CFDictionaryGetValue(expected,service.path),previous=CFDictionaryGetValue(observed,service.path);
        if (!value || value==previous || (value!=kCFNull && previous!=kCFNull && CFEqual(value,previous))) continue;
        if (!write(api,prefs,service.path,value==kCFNull ? nullptr : static_cast<CFDictionaryRef>(value)))
            return error("Restore proxy preferences",true);
    }
    if (changed && !api.commit(prefs)) return error("Commit restored proxy preferences", true);
    SCPreferencesSynchronize(prefs);
    for (const auto &service : saved->services) {
        auto target = CFDictionaryGetValue(expected, service.path);
        if (!target) continue;
        CFDictionaryRef actual = nullptr;
        const bool verified = read(prefs, service.path, actual).succeeded() && (target == kCFNull ? actual == nullptr : actual && CFEqual(actual, target));
        if (!verified) return {Status::Failed, "Restored proxy preferences readback mismatch", true};
    }
    for (auto &service : saved->services) {
        service.released|=service.pendingRestore;service.pendingRestore=0;
    }
    saved->restorationCommitted=!unresolved;
    if (auto result=checkpoint();!result.succeeded()) return result;
    if (!api.apply(prefs)) return error("Apply restored proxy preferences", true);
    if (unresolved) return {Status::Failed,"Unconfirmed macOS proxy ownership; matching values retained",true};
    if (auto result=checkpoint(true);!result.succeeded()) return result;
    snapshot.reset(); return {};
}
