#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyvalidation.h"
#include <QStandardPaths>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
bool kde() { return qEnvironmentVariable("XDG_CURRENT_DESKTOP").contains("KDE", Qt::CaseInsensitive)
    || qEnvironmentVariable("XDG_SESSION_DESKTOP").compare("plasma", Qt::CaseInsensitive) == 0; }
bool gnome() {
    const auto desktop = qEnvironmentVariable("XDG_CURRENT_DESKTOP") + ':' + qEnvironmentVariable("XDG_SESSION_DESKTOP");
    return desktop.contains("GNOME", Qt::CaseInsensitive) || desktop.contains("Unity", Qt::CaseInsensitive)
        || desktop.contains("Cinnamon", Qt::CaseInsensitive);
}
QString kdeTool(const char *prefix) { return QString::fromLatin1(prefix) + qEnvironmentVariable("KDE_SESSION_VERSION"); }
QStringList kdeArgs(const QString &key) {
    return {"--file", QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/kioslaverc",
            "--group", "Proxy Settings", "--key", key};
}
// gsettings prints GVariant strings, which may use either quote style.
QStringList strings(const QString &value, bool &ok, bool array) {
    QString input = value.trimmed();
    if (input.startsWith("@as ")) input.remove(0,4);
    ok = false;
    if (input.isEmpty()) return {};
    if (array) {
        if (!input.startsWith('[') || !input.endsWith(']')) return {};
        input = input.mid(1,input.size()-2).trimmed();
    }
    QStringList values; qsizetype i = 0;
    while (i < input.size()) {
        while (i < input.size() && input[i].isSpace()) ++i;
        if (i == input.size()) break;
        const auto quote = input[i++];
        if (quote != '\'' && quote != '"') return {};
        QString item; bool closed = false;
        while (i < input.size()) {
            auto ch = input[i++];
            if (ch == quote) { closed = true; break; }
            if (ch == '\\') {
                if (i == input.size()) return {};
                ch = input[i++];
                if (ch != '\\' && ch != '\'' && ch != '"') return {};
            }
            item += ch;
        }
        if (!closed) return {};
        values.append(item);
        while (i < input.size() && input[i].isSpace()) ++i;
        if (i == input.size()) break;
        if (!array || input[i++] != ',') return {};
    }
    ok = array || values.size() == 1;
    return values;
}

Result available() {
    if (!kde() && !gnome()) return {Status::Unsupported, "Desktop system proxy is unsupported"};
    if (kde() && qEnvironmentVariable("KDE_SESSION_VERSION") != "5" && qEnvironmentVariable("KDE_SESSION_VERSION") != "6")
        return {Status::Unsupported, "KDE session version is unsupported"};
    return {};
}
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    if (auto support = available(); !support.succeeded()) return {support};
    if (kde()) {
        auto modeArgs = kdeArgs("ProxyType"); modeArgs << "--default" << "0";
        auto mode = runner(kdeTool("kreadconfig"), modeArgs);
        if (!mode.result.succeeded()) return {mode.result};
        if (mode.output == "0" || mode.output.isEmpty()) return {{}, false};
        if (mode.output != "1") return {{}, true};
        for (const auto &protocol : {QString("http"), QString("https"), QString("ftp"), QString("socks")}) {
            auto current = runner(kdeTool("kreadconfig"), kdeArgs(protocol + "Proxy"));
            if (!current.result.succeeded()) return {current.result};
            const auto expected = (protocol == "socks" ? "socks://127.0.0.1 " : "http://127.0.0.1 ")
                + QString::number(protocol == "socks" ? config.socksPort : config.httpPort);
            if (current.output != expected) return {{}, true};
        }
        return {{}, false, true};
    }
    auto mode = runner("gsettings", {"get", "org.gnome.system.proxy", "mode"});
    if (!mode.result.succeeded()) return {mode.result};
    bool ok = false; const auto values = strings(mode.output, ok, false);
    if (!ok || values.size() != 1 || !QStringList{"none", "manual", "auto"}.contains(values[0]))
        return {{Status::Failed, "Invalid GNOME proxy mode"}};
    if (values[0] != "manual") return {{}, values[0] == "auto"};
    auto same = runner("gsettings", {"get", "org.gnome.system.proxy", "use-same-proxy"});
    if (!same.result.succeeded()) return {same.result};
    if (same.output == "true") return {{}, true, true};
    if (same.output != "false") return {{Status::Failed, "Invalid shared proxy flag"}};
    auto authenticated = runner("gsettings", {"get", "org.gnome.system.proxy.http", "use-authentication"});
    if (!authenticated.result.succeeded()) return {authenticated.result};
    if (authenticated.output == "true") return {{}, true, true};
    if (authenticated.output != "false") return {{Status::Failed, "Invalid HTTP proxy authentication flag"}};
    for (const auto &protocol : {QString("http"), QString("https"), QString("ftp"), QString("socks")}) {
        auto host = runner("gsettings", {"get", "org.gnome.system.proxy." + protocol, "host"});
        if (!host.result.succeeded()) return {host.result};
        auto port = runner("gsettings", {"get", "org.gnome.system.proxy." + protocol, "port"});
        if (!port.result.succeeded()) return {port.result};
        const auto hosts = strings(host.output, ok, false);
        if (!ok || hosts.size() != 1) return {{Status::Failed, "Invalid GNOME proxy host"}};
        const int number = port.output.toInt(&ok);
        if (!ok || number < 0 || number > 65535) return {{Status::Failed, "Invalid GNOME proxy port"}};
        if (hosts[0] != "127.0.0.1" || number != (protocol == "socks" ? config.socksPort : config.httpPort)) return {{}, true};
    }
    return {{}, false, true};
}

PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return valid;
    if (auto support = available(); !support.succeeded()) return support;
    // Verify the query path before the first mutation; an error is not permission to overwrite.
    if (auto before = check(config); !before.result.succeeded()) return before.result;
    QList<QPair<QString, QStringList>> commands;
    const auto add = [&](const QString &schema, const QString &key, const QString &value) {
        if (kde()) { auto args = kdeArgs(key); args.append(value); commands.append({kdeTool("kwriteconfig"), args}); }
        else commands.append({"gsettings", {"set", schema, key, value}});
    };
    for (const auto &protocol : {QString("http"), QString("https"), QString("ftp"), QString("socks")}) {
        const QString port = QString::number(protocol == "socks" ? config.socksPort : config.httpPort);
        if (kde()) add({}, protocol + "Proxy", (protocol == "socks" ? "socks://127.0.0.1 " : "http://127.0.0.1 ") + port);
        else { add("org.gnome.system.proxy." + protocol, "host", "'127.0.0.1'"); add("org.gnome.system.proxy." + protocol, "port", port); }
    }
    if (!kde()) {
        add("org.gnome.system.proxy", "use-same-proxy", "false");
        add("org.gnome.system.proxy.http", "use-authentication", "false");
    }
    const auto bypass = ProxyValidation::bypass(config.bypass);
    add("org.gnome.system.proxy", kde() ? "NoProxyFor" : "ignore-hosts", kde() ? bypass.join(',') : ProxyValidation::listValue(bypass));
    add("org.gnome.system.proxy", kde() ? "ProxyType" : "mode", kde() ? "1" : "'manual'");
    if (kde()) commands.append({"dbus-send", {"--session", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"}});
    for (const auto &command : commands) {
        auto result = runner(command.first, command.second).result;
        if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    }
    auto verified = check(config);
    if (!verified.result.succeeded()) { verified.result.mayHaveChanged = true; return verified.result; }
    if (verified.conflict || !verified.active) return {Status::Failed, "Proxy readback does not match requested endpoints", true};
    auto bypassResult = kde() ? runner(kdeTool("kreadconfig"), kdeArgs("NoProxyFor"))
        : runner("gsettings", {"get", "org.gnome.system.proxy", "ignore-hosts"});
    if (!bypassResult.result.succeeded()) { bypassResult.result.mayHaveChanged = true; return bypassResult.result; }
    bool ok = true;
    const auto actual = kde() ? bypassResult.output.split(',', Qt::SkipEmptyParts) : strings(bypassResult.output, ok, true);
    if (!ok || actual != bypass) return {Status::Failed, "Proxy bypass readback does not match", true};
    return {Status::Success, {}, true};
}

PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (auto support = available(); !support.succeeded()) return support;
    auto args = kdeArgs("ProxyType"); args.append("0");
    auto result = kde() ? runner(kdeTool("kwriteconfig"), args)
        : runner("gsettings", {"set", "org.gnome.system.proxy", "mode", "'none'"});
    if (!result.result.succeeded()) { result.result.mayHaveChanged = true; return result.result; }
    if (kde()) {
        result = runner("dbus-send", {"--session", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"});
        if (!result.result.succeeded()) { result.result.mayHaveChanged = true; return result.result; }
    }
    result = kde() ? runner(kdeTool("kreadconfig"), kdeArgs("ProxyType"))
        : runner("gsettings", {"get", "org.gnome.system.proxy", "mode"});
    if (!result.result.succeeded()) { result.result.mayHaveChanged = true; return result.result; }
    if (result.output != (kde() ? "0" : "'none'")) return {Status::Failed, "Proxy disable readback failed", true};
    return {Status::Success, {}, true};
}
