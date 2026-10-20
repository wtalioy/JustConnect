#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyvalidation.h"
#include <raserror.h>
#include <vector>

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
struct State { DWORD flags = 0; QString server, bypass; };
Result query(const WindowsProxyApi &api, const QString &name, State &state) {
    INTERNET_PER_CONN_OPTIONW options[3]{};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.pszConnection = name.isEmpty() ? nullptr : const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(name.utf16()));
    list.dwOptionCount = 3; list.pOptions = options;
    DWORD bytes = sizeof(list);
    const BOOL success = api.query(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &bytes);
    const DWORD code = success ? ERROR_SUCCESS : GetLastError();
    state.flags = options[0].Value.dwValue;
    QString *strings[] = {&state.server, &state.bypass};
    for (int i=1; i<3; ++i) {
        *strings[i-1] = QString::fromWCharArray(options[i].Value.pszValue ? options[i].Value.pszValue : L"");
        if (options[i].Value.pszValue) GlobalFree(options[i].Value.pszValue);
    }
    return success ? Result{} : error("Query WinINet proxy", code);
}
QString server(const SystemProxyConfig &config) {
    const auto http = "127.0.0.1:" + QString::number(config.httpPort);
    return "http=" + http + ";https=" + http + ";ftp=" + http + ";socks=127.0.0.1:" + QString::number(config.socksPort);
}
Result set(const WindowsProxyApi &api, const QString &name, const SystemProxyConfig *config) {
    QString proxy = config ? server(*config) : QString();
    QString bypass = config ? ProxyValidation::bypass(config->bypass).join(';') : QString();
    INTERNET_PER_CONN_OPTIONW options[3]{};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = config ? PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY : PROXY_TYPE_DIRECT;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(proxy.utf16()));
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(bypass.utf16()));
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list); list.dwOptionCount = config ? 3 : 1; list.pOptions = options;
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
    if (auto before = check(config); !before.result.succeeded()) return before.result;
    QStringList names;
    if (auto result = connections(api, names); !result.succeeded()) return result;
    for (const auto &name : names) {
        auto result = set(api, name, &config);
        if (!result.succeeded()) return result;
        State actual;
        result = query(api, name, actual);
        if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
        if (actual.flags != (PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY) || actual.server != server(config)
            || actual.bypass != ProxyValidation::bypass(config.bypass).join(';'))
            return {Status::Failed, "WinINet proxy readback mismatch", true};
    }
    return notify(api);
}
PlatformOperationResult PlatformSystemProxyBackend::clear() {
    QStringList names;
    if (auto result = connections(api, names); !result.succeeded()) return result;
    for (const auto &name : names) {
        auto result = set(api, name, nullptr);
        if (!result.succeeded()) return result;
        State actual;
        result = query(api, name, actual);
        if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
        if (actual.flags != PROXY_TYPE_DIRECT) return {Status::Failed, "WinINet disable readback mismatch", true};
    }
    return notify(api);
}
