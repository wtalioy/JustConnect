#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/proxyvalidation.h"
#include "application/credentialstore.h"
#include <raserror.h>
#include <vector>
#include <QMap>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSysInfo>
#include <QUuid>
#include <limits>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result error(const QString &operation, DWORD code, bool changed = false) {
    Status status = Status::Failed;
    if (code == ERROR_CANCELLED) status = Status::Cancelled;
    else if (code == ERROR_ACCESS_DENIED) status = Status::PermissionDenied;
    else if (code == ERROR_TIMEOUT || code == ERROR_INTERNET_TIMEOUT) status = Status::TimedOut;
    else if (code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED) status = Status::Unsupported;
    return {status, operation + ": Windows error " + QString::number(code), changed};
}
Result connections(const WindowsProxyApi &api, QStringList &names) {
    DWORD bytes = 0, count = 0;
    DWORD status = api.entries(nullptr, nullptr, nullptr, &bytes, &count);
    names.append(QString()); // LAN uses a null connection name.
    if (status == ERROR_SUCCESS && count == 0) return {};
    if (status != ERROR_BUFFER_TOO_SMALL) return error("Enumerate RAS connections", status);
    if (bytes < sizeof(RASENTRYNAMEW) || bytes > 1024*1024) return {Status::Failed, "Invalid RAS buffer size"};
    std::vector<RASENTRYNAMEW> entries((bytes + sizeof(RASENTRYNAMEW)-1)/sizeof(RASENTRYNAMEW));
    entries[0].dwSize = sizeof(RASENTRYNAMEW);
    bytes = DWORD(entries.size()*sizeof(RASENTRYNAMEW));
    status = api.entries(nullptr, nullptr, entries.data(), &bytes, &count);
    if (status != ERROR_SUCCESS) return error("Enumerate RAS connections", status);
    if (count > entries.size()) return {Status::Failed, "Invalid RAS connection count"};
    for (DWORD i=0; i<count; ++i) names.append(QString::fromWCharArray(entries[i].szEntryName));
    return {};
}
struct State { DWORD flags = 0; QString server, bypass, pac; };
Result query(const WindowsProxyApi &api, const QString &name, State &state) {
    INTERNET_PER_CONN_OPTIONW options[4]{};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.pszConnection = name.isEmpty() ? nullptr : const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(name.utf16()));
    list.dwOptionCount = 4; list.pOptions = options;
    DWORD bytes = sizeof(list);
    const BOOL success = api.query(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &bytes);
    const DWORD code = success ? ERROR_SUCCESS : GetLastError();
    state.flags = options[0].Value.dwValue;
    QString *strings[] = {&state.server, &state.bypass, &state.pac};
    for (int i=1; i<4; ++i) {
        *strings[i-1] = QString::fromWCharArray(options[i].Value.pszValue ? options[i].Value.pszValue : L"");
        if (options[i].Value.pszValue) GlobalFree(options[i].Value.pszValue);
    }
    return success ? Result{} : error("Query WinINet proxy", code);
}
QString server(const SystemProxyConfig &config) {
    const auto http = "127.0.0.1:" + QString::number(config.httpPort);
    return "http=" + http + ";https=" + http + ";ftp=" + http + ";socks=127.0.0.1:" + QString::number(config.socksPort);
}
QStringList proxyEndpoints(const State &state) {
    if (!(state.flags & PROXY_TYPE_PROXY) || (state.flags & (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT))) return {};
    QStringList result;
    for (auto part : state.server.split(';',Qt::SkipEmptyParts)) {
        part=part.trimmed();
        const auto equals=part.indexOf('=');
        if (equals>=0) {
            if (!QStringList{"http","https","ftp","socks"}.contains(part.left(equals))) return {};
            part=part.mid(equals+1);
        }
        const auto endpoint=ProxyValidation::endpoint(part);
        if (endpoint.isEmpty()) return {};
        if (!result.contains(endpoint)) result.append(endpoint);
    }
    return result;
}
Result set(const WindowsProxyApi &api, const QString &name, const State &state,
           bool flags = true, bool proxy = true, bool bypass = true) {
    INTERNET_PER_CONN_OPTIONW options[3]{};
    DWORD count = 0;
    if (flags) { options[count].dwOption = INTERNET_PER_CONN_FLAGS; options[count++].Value.dwValue = state.flags; }
    if (proxy) { options[count].dwOption = INTERNET_PER_CONN_PROXY_SERVER; options[count++].Value.pszValue = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(state.server.utf16())); }
    if (bypass) { options[count].dwOption = INTERNET_PER_CONN_PROXY_BYPASS; options[count++].Value.pszValue = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(state.bypass.utf16())); }
    if (!count) return {};
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list); list.dwOptionCount = count; list.pOptions = options;
    list.pszConnection = name.isEmpty() ? nullptr : const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(name.utf16()));
    if (!api.set(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) return error("Set WinINet proxy", GetLastError(), true);
    return {Status::Success, {}, true};
}
Result notify(const WindowsProxyApi &api) {
    for (DWORD option : {DWORD(INTERNET_OPTION_SETTINGS_CHANGED), DWORD(INTERNET_OPTION_REFRESH)})
        if (!api.set(nullptr, option, nullptr, 0)) return error("Notify WinINet proxy", GetLastError(), true);
    return {Status::Success, {}, true};
}
}
struct PlatformSystemProxyBackend::Snapshot {
    enum Field : unsigned { Flags=1, Proxy=2, Bypass=4 };
    struct Connection {
        State before;
        unsigned released = 0, intent = 0, written = 0, uncertain = 0, pendingRestore = 0;
    };
    QMap<QString, Connection> connections;
    State installed;
    SystemProxyConfig config;
    QUuid owner = QUuid::createUuid();
    bool dirty = false, resumed = false;
};

QJsonObject PlatformSystemProxyBackend::recoverySnapshot() const {
    if (!snapshot) return {};
    QJsonArray connections;
    for (auto it=snapshot->connections.cbegin();it!=snapshot->connections.cend();++it) {
        const auto &state=it->before;
        connections.append(QJsonObject{{"name",it.key()},{"flags",qint64(state.flags)},
            {"server",state.server},{"bypass",state.bypass},{"pac",state.pac},{"released",qint64(it->released)},
            {"intent",qint64(it->intent)},{"written",qint64(it->written)},
            {"uncertain",qint64(it->uncertain)},{"pending_restore",qint64(it->pendingRestore)}});
    }
    return {{"schema_version",3},{"platform","windows"},
        {"machine",QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"owner",snapshot->owner.toString(QUuid::WithoutBraces)},
        {"config",ProxyValidation::json(snapshot->config)},
        {"connections",connections}};
}

PlatformOperationResult PlatformSystemProxyBackend::checkpoint(bool remove) {
    auto result=checkpointWriter?checkpointWriter(remove?QJsonObject{}:recoverySnapshot()):Result{};
    if (!result.succeeded() && snapshot && snapshot->dirty) result.mayHaveChanged=true;
    return result;
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed,"Existing system proxy ownership must be restored first",true};
    const auto invalid=[] { return Result{Status::Failed,"Invalid or foreign Windows proxy recovery record"}; };
    const auto bytes=QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine=QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText=record["owner"].toString();const QUuid owner(ownerText);
    if (bytes.size()>CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object()!=record || record.size()!=6
        || record["schema_version"]!=3 || record["platform"]!="windows" || machine.isEmpty()
        || record["machine"]!=machine || owner.isNull() || owner.toString(QUuid::WithoutBraces)!=ownerText
        || !record["config"].isObject() || !record["connections"].isArray()) return invalid();
    const auto config=ProxyValidation::parse(record["config"].toObject());
    if (!config) return invalid();
    auto pending=std::make_shared<Snapshot>();pending->owner=owner;
    pending->config=*config;
    if (!ProxyValidation::config(pending->config).succeeded()) return invalid();
    pending->installed={PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY,server(pending->config),ProxyValidation::bypass(pending->config.bypass).join(';'),{}};
    const auto connections=record["connections"].toArray();
    // An empty list retains only the activation notification after confirmed restoration.
    pending->dirty=connections.isEmpty();
    for (const auto &value:connections) {
        if (!value.isObject()) return invalid();
        const auto connection=value.toObject();const auto flags=connection["flags"].toInteger(-1);
        if (connection.size()!=10 || flags<0 || quint64(flags)>(std::numeric_limits<DWORD>::max)()) return invalid();
        Snapshot::Connection entry;entry.before.flags=DWORD(flags);
        for (const auto &field:std::initializer_list<std::pair<const char *,unsigned *>>{
                 {"released",&entry.released},{"intent",&entry.intent},{"written",&entry.written},
                 {"uncertain",&entry.uncertain},{"pending_restore",&entry.pendingRestore}}) {
            const auto value=connection[field.first].toInteger(-1);
            if (value<0 || value>7) return invalid();
            *field.second=unsigned(value);
        }
        if ((entry.written&~entry.intent) || (entry.uncertain&~entry.intent) || (entry.released&entry.uncertain)
            || (entry.pendingRestore&(~entry.intent|entry.released|entry.uncertain))) return invalid();
        for (const auto *key:{"name","server","bypass","pac"})
            if (!connection[key].isString() || connection[key].toString().contains(QChar(0))) return invalid();
        const auto name=connection["name"].toString();
        if (name.size()>RAS_MaxEntryName || pending->connections.contains(name)) return invalid();
        entry.before.server=connection["server"].toString();entry.before.bypass=connection["bypass"].toString();entry.before.pac=connection["pac"].toString();
        pending->dirty|=entry.intent!=0;pending->connections.insert(name,entry);
    }
    pending->resumed=true;snapshot=pending;
    return clear();
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    return observe(&config);
}
SystemProxyCheck PlatformSystemProxyBackend::inspect() { return observe(nullptr); }
SystemProxyCheck PlatformSystemProxyBackend::observe(const SystemProxyConfig *config) {
    QStringList names, endpoints;
    if (auto result = connections(api, names); !result.succeeded()) return {result};
    bool active = false, conflict = false, managed = false;
    for (const auto &name : names) {
        State state;
        if (auto result = query(api, name, state); !result.succeeded()) return {result};
        const bool enabled=(state.flags & PROXY_TYPE_PROXY)!=0;
        active |= enabled;
        conflict |= (state.flags & (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT)) != 0
            || (config && enabled && state.server != server(*config));
        if (!enabled) continue;
        const bool own=snapshot && snapshot->connections.contains(name) && state.server==snapshot->installed.server
            && state.flags==snapshot->installed.flags && state.pac==snapshot->connections[name].before.pac;
        managed |= own;
        for (const auto &endpoint:proxyEndpoints(own?snapshot->connections[name].before:state))
            if (!endpoints.contains(endpoint)) endpoints.append(endpoint);
    }
    return {{}, conflict, active, managed && active, endpoints};
}
PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return valid;
    if (snapshot) return {Status::Failed, "Restore the current proxy settings before applying another configuration", true};
    QStringList names;
    if (auto result = connections(api, names); !result.succeeded()) return result;
    auto pending = std::make_shared<Snapshot>();
    pending->config = config;
    for (const auto &name : names) {
        State state;
        if (auto result = query(api, name, state); !result.succeeded()) return result;
        if (!config.upstream.isEmpty() && !ProxyValidation::matches(config.upstream,proxyEndpoints(state))) continue;
        pending->connections.insert(name, {state,0});
    }
    if (pending->connections.isEmpty()) return {Status::Failed,"System proxy changed before automatic handoff"};
    pending->installed = {PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, server(config), ProxyValidation::bypass(config.bypass).join(';'), {}};
    snapshot = pending;
    if (auto result=checkpoint();!result.succeeded()) {
        if (!result.mayHaveChanged) snapshot.reset();
        return result;
    }
    const auto fail = [this](Result result) { const auto restored = clear(); result.mayHaveChanged = !restored.succeeded(); return result; };
    for (const auto &name : pending->connections.keys()) {
        auto &entry=pending->connections[name];
        entry.intent=(entry.before.flags!=pending->installed.flags?Snapshot::Flags:0)
            |(entry.before.server!=pending->installed.server?Snapshot::Proxy:0)
            |(config.upstream.isEmpty() && entry.before.bypass!=pending->installed.bypass?Snapshot::Bypass:0);
        if (!entry.intent) continue;
        const auto abandon=[&](Result result) {entry.intent=0;entry.released=7;return fail(result);};
        if (auto result=checkpoint();!result.succeeded()) return abandon(result);
        State current;
        if (auto result=query(api,name,current);!result.succeeded()) return abandon(result);
        if (current.flags!=entry.before.flags || current.server!=entry.before.server
            || current.bypass!=entry.before.bypass || current.pac!=entry.before.pac)
            return abandon({Status::Failed,"Proxy settings changed before application"});
        pending->dirty=true;
        auto result = set(api, name, pending->installed,entry.intent&Snapshot::Flags,entry.intent&Snapshot::Proxy,entry.intent&Snapshot::Bypass);
        if (!result.succeeded()) return fail(result);
        State actual;
        result = query(api, name, actual);
        if (!result.succeeded()) return fail(result);
        if (actual.flags != pending->installed.flags || actual.server != pending->installed.server
            || actual.bypass != (config.upstream.isEmpty()?pending->installed.bypass:entry.before.bypass) || actual.pac != pending->connections[name].before.pac)
            return fail({Status::Failed, "WinINet proxy readback mismatch", true});
        entry.written=entry.intent;
        if (auto result=checkpoint();!result.succeeded()) return fail(result);
    }
    if (auto result = notify(api); !result.succeeded()) return fail(result);
    return {Status::Success, {}, true};
}
PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (!snapshot) return {};
    auto &saved = *snapshot;
    const auto failed = [](Result result) { result.mayHaveChanged = true; return result; };
    if (!saved.dirty) {
        if (auto result=checkpoint(true);!result.succeeded()) return failed(result);
        snapshot.reset();return {};
    }
    const auto releaseObserved=[&](Snapshot::Connection &entry,const State &value) {
        const auto &before=entry.before;
        entry.released|=7&~entry.intent;
        if(value.server==before.server || value.server!=saved.installed.server)entry.released|=Snapshot::Proxy;
        if(value.bypass==before.bypass || value.bypass!=saved.installed.bypass)entry.released|=Snapshot::Bypass;
        if(value.flags==before.flags || value.flags!=saved.installed.flags || value.pac!=before.pac
            || ((entry.released&Snapshot::Proxy) && value.server!=before.server))entry.released|=Snapshot::Flags;
        entry.uncertain&=~entry.released;entry.pendingRestore&=~entry.released;
    };
    if (saved.resumed) {
        for (auto it=saved.connections.begin();it!=saved.connections.end();++it) {
            auto &entry=it.value();const auto pending=entry.pendingRestore;
            const auto unconfirmed=((entry.intent&~entry.written)|pending)&~entry.released;
            // Save before observing originals: a crash may otherwise lose a released field's ownership.
            entry.pendingRestore=entry.intent&~(entry.released|entry.uncertain);
            if (auto result=checkpoint();!result.succeeded()) {entry.pendingRestore=pending;return failed(result);}
            State current;
            if (auto result=query(api,it.key(),current);!result.succeeded()) {entry.pendingRestore=pending;return failed(result);}
            releaseObserved(entry,current);
            // A lost acknowledgement cannot distinguish our setting from an external same-value recreation.
            entry.uncertain|=unconfirmed&~entry.released;
            entry.pendingRestore=0;
            if (auto result=checkpoint();!result.succeeded()) return failed(result);
        }
        saved.resumed=false;
    }
    for (auto it = saved.connections.begin(); it != saved.connections.end();) {
        auto &entry=it.value();const auto &before = entry.before; State current;
        entry.pendingRestore=entry.intent&~(entry.released|entry.uncertain);
        if (auto result=checkpoint();!result.succeeded()) return failed(result);
        if (auto result = query(api, it.key(), current); !result.succeeded()) return failed(result);
        releaseObserved(entry,current);
        for (;;) {
            auto fields=entry.intent&~(entry.released|entry.uncertain);
            if ((entry.uncertain&Snapshot::Proxy) && current.server!=before.server) fields&=~Snapshot::Flags;
            entry.pendingRestore=fields;
            if (auto result=checkpoint();!result.succeeded()) return failed(result);
            if (!fields) break;
            const auto released=entry.released;
            if (auto result=query(api,it.key(),current);!result.succeeded()) return failed(result);
            releaseObserved(entry,current);
            if (released!=entry.released) continue;
            if (auto result=set(api,it.key(),before,fields&Snapshot::Flags,fields&Snapshot::Proxy,fields&Snapshot::Bypass);!result.succeeded()) return failed(result);
            State actual;
            if (auto result=query(api,it.key(),actual);!result.succeeded()) return failed(result);
            releaseObserved(entry,actual);
            if (auto result=checkpoint();!result.succeeded()) return failed(result);
            if (((fields&Snapshot::Proxy) && actual.server!=before.server)
                || ((fields&Snapshot::Bypass) && actual.bypass!=before.bypass)
                || ((fields&Snapshot::Flags) && actual.flags!=before.flags))
                return {Status::Failed,"WinINet restoration readback mismatch",true};
            break;
        }
        if (entry.released==7) it=saved.connections.erase(it);else ++it;
    }
    if (auto result = notify(api); !result.succeeded()) return result;
    if (!saved.connections.isEmpty()) return {Status::Failed,"Unconfirmed proxy settings retained; external ownership cannot be determined",true};
    if (auto result=checkpoint(true);!result.succeeded()) return failed(result);
    snapshot.reset(); return {};
}
