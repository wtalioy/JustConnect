#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyvalidation.h"
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
    struct Connection { State before; unsigned released = 0; };
    QMap<QString, Connection> connections;
    State installed;
    SystemProxyConfig config;
    QUuid owner = QUuid::createUuid();
};

QJsonObject PlatformSystemProxyBackend::recoverySnapshot() const {
    if (!snapshot) return {};
    QJsonArray connections;
    for (auto it=snapshot->connections.cbegin();it!=snapshot->connections.cend();++it) {
        const auto &state=it->before;
        connections.append(QJsonObject{{"name",it.key()},{"flags",qint64(state.flags)},
            {"server",state.server},{"bypass",state.bypass},{"pac",state.pac},{"released",qint64(it->released)}});
    }
    return {{"schema_version",2},{"platform","windows"},
        {"machine",QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"owner",snapshot->owner.toString(QUuid::WithoutBraces)},
        {"config",QJsonObject{{"http_port",snapshot->config.httpPort},
            {"socks_port",snapshot->config.socksPort},{"bypass",snapshot->config.bypass}}},
        {"connections",connections}};
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed,"Existing system proxy ownership must be restored first",true};
    const auto invalid=[] { return Result{Status::Failed,"Invalid or foreign Windows proxy recovery record"}; };
    const auto bytes=QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine=QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText=record["owner"].toString();const QUuid owner(ownerText);
    if (bytes.size()>CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object()!=record || record.size()!=6
        || record["schema_version"]!=2 || record["platform"]!="windows" || machine.isEmpty()
        || record["machine"]!=machine || owner.isNull() || owner.toString(QUuid::WithoutBraces)!=ownerText
        || !record["config"].isObject() || !record["connections"].isArray()) return invalid();
    const auto config=record["config"].toObject();
    const auto http=config["http_port"].toInteger(-1),socks=config["socks_port"].toInteger(-1);
    if (config.size()!=3 || http<1 || http>65535 || socks<1 || socks>65535 || !config["bypass"].isString()) return invalid();
    auto pending=std::make_shared<Snapshot>();pending->owner=owner;
    pending->config={int(http),int(socks),config["bypass"].toString()};
    if (!ProxyValidation::config(pending->config).succeeded()) return invalid();
    pending->installed={PROXY_TYPE_DIRECT|PROXY_TYPE_PROXY,server(pending->config),ProxyValidation::bypass(pending->config.bypass).join(';'),{}};
    const auto connections=record["connections"].toArray();
    for (const auto &value:connections) {
        if (!value.isObject()) return invalid();
        const auto connection=value.toObject();const auto flags=connection["flags"].toInteger(-1);
        const auto released=connection["released"].toInteger(-1);
        if (connection.size()!=6 || flags<0 || quint64(flags)>(std::numeric_limits<DWORD>::max)()
            || released<0 || released>7) return invalid();
        for (const auto *key:{"name","server","bypass","pac"})
            if (!connection[key].isString() || connection[key].toString().contains(QChar(0))) return invalid();
        const auto name=connection["name"].toString();
        if (name.size()>RAS_MaxEntryName || pending->connections.contains(name)) return invalid();
        pending->connections.insert(name,{{DWORD(flags),connection["server"].toString(),connection["bypass"].toString(),connection["pac"].toString()},unsigned(released)});
    }
    snapshot=pending;
    return clear();
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    QStringList names;
    if (auto result = connections(api, names); !result.succeeded()) return {result};
    bool active = false, conflict = false;
    for (const auto &name : names) {
        State state;
        if (auto result = query(api, name, state); !result.succeeded()) return {result};
        active |= (state.flags & PROXY_TYPE_PROXY) != 0;
        conflict |= (state.flags & (PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT)) != 0
            || ((state.flags & PROXY_TYPE_PROXY) && state.server != server(config));
    }
    return {{}, conflict, active};
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
        pending->connections.insert(name, {state,0});
    }
    pending->installed = {PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, server(config), ProxyValidation::bypass(config.bypass).join(';'), {}};
    snapshot = pending;
    const auto fail = [this](Result result) { const auto restored = clear(); result.mayHaveChanged = !restored.succeeded(); return result; };
    for (const auto &name : names) {
        auto result = set(api, name, pending->installed);
        if (!result.succeeded()) return fail(result);
        State actual;
        result = query(api, name, actual);
        if (!result.succeeded()) return fail(result);
        if (actual.flags != pending->installed.flags || actual.server != pending->installed.server
            || actual.bypass != pending->installed.bypass || actual.pac != pending->connections[name].before.pac)
            return fail({Status::Failed, "WinINet proxy readback mismatch", true});
    }
    if (auto result = notify(api); !result.succeeded()) return fail(result);
    return {Status::Success, {}, true};
}
PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (!snapshot) return {};
    auto &saved = *snapshot;
    const auto failed = [](Result result) { result.mayHaveChanged = true; return result; };
    for (auto it = saved.connections.begin(); it != saved.connections.end();) {
        auto &entry=it.value();const auto &before = entry.before; State current;
        const auto releaseObserved=[&](const State &value) {
            if(value.server==before.server || value.server!=saved.installed.server)entry.released|=Snapshot::Proxy;
            if(value.bypass==before.bypass || value.bypass!=saved.installed.bypass)entry.released|=Snapshot::Bypass;
            if(value.flags==before.flags || value.flags!=saved.installed.flags || value.pac!=before.pac
                || ((entry.released&Snapshot::Proxy) && value.server!=before.server))entry.released|=Snapshot::Flags;
        };
        if (auto result = query(api, it.key(), current); !result.succeeded()) return failed(result);
        // Release each observed original before another field's restore can fail or lose its acknowledgement.
        releaseObserved(current);
        const bool proxy = !(entry.released&Snapshot::Proxy);
        const bool bypass = !(entry.released&Snapshot::Bypass);
        const bool flags = !(entry.released&Snapshot::Flags);
        if (!proxy && !bypass && !flags) { it=saved.connections.erase(it);continue; }
        if (auto result = set(api, it.key(), before, flags, proxy, bypass); !result.succeeded()) return failed(result);
        State actual;
        if (auto result = query(api, it.key(), actual); !result.succeeded()) return failed(result);
        releaseObserved(actual);
        if ((proxy && actual.server != before.server) || (bypass && actual.bypass != before.bypass)
            || (flags && actual.flags != before.flags)) return {Status::Failed, "WinINet restoration readback mismatch", true};
        it=saved.connections.erase(it);
    }
    if (auto result = notify(api); !result.succeeded()) return result;
    snapshot.reset(); return {};
}
