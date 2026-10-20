#include "platformsystemproxybackend.h"
#include "proxyvalidation.h"
#include <QMap>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
const QString tool = "/usr/sbin/networksetup";
const QStringList types{"webproxy", "securewebproxy", "socksfirewallproxy"};
Result services(const PlatformCommandRunner &run, QStringList &names) {
    auto command = run(tool, {"-listallnetworkservices"});
    if (!command.result.succeeded()) return command.result;
    auto lines = command.output.split('\n', Qt::SkipEmptyParts);
    if (lines.isEmpty() || !lines.takeFirst().startsWith("An asterisk (*)"))
        return {Status::Failed, "Invalid network service list"};
    for (auto line : lines) {
        line = line.trimmed();
        if (!line.isEmpty() && !line.startsWith('*')) names.append(line);
    }
    if (names.isEmpty()) return {Status::Unsupported, "No enabled network services"};
    return {};
}
QMap<QString, QString> fields(const QString &output) {
    QMap<QString, QString> result;
    for (const auto &line : output.split('\n')) {
        const auto colon = line.indexOf(':');
        if (colon > 0) result.insert(line.left(colon).trimmed(), line.mid(colon+1).trimmed());
    }
    return result;
}
}
SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    QStringList names;
    if (auto result = services(runner, names); !result.succeeded()) return {result};
    bool active = false, conflict = false;
    for (const auto &name : names) {
        for (const auto &type : types) {
            auto command = runner(tool, {"-get" + type, name});
            if (!command.result.succeeded()) return {command.result};
            const auto data = fields(command.output);
            if (data["Enabled"] == "No") continue;
            if (data["Enabled"] != "Yes") return {{Status::Failed, "Missing proxy enabled state"}};
            const auto auth = data.value("Authenticated Proxy Enabled");
            if (auth != "0" && auth != "1") return {{Status::Failed, "Missing proxy authentication state"}};
            conflict |= auth == "1";
            active = true;
            bool ok = false; const int port = data["Port"].toInt(&ok);
            if (!ok || port < 1 || port > 65535 || data["Server"].isEmpty())
                return {{Status::Failed, "Invalid proxy endpoint readback"}};
            conflict |= data["Server"] != "127.0.0.1" || port != (type == "socksfirewallproxy" ? config.socksPort : config.httpPort);
        }
        auto pac = runner(tool, {"-getautoproxyurl", name});
        if (!pac.result.succeeded()) return {pac.result};
        const auto enabled = fields(pac.output).value("Enabled");
        if (enabled != "Yes" && enabled != "No") return {{Status::Failed, "Missing PAC enabled state"}};
        auto discovery = runner(tool, {"-getproxyautodiscovery", name});
        if (!discovery.result.succeeded()) return {discovery.result};
        const auto automatic = fields(discovery.output).value("Auto Proxy Discovery");
        if (automatic != "On" && automatic != "Off") return {{Status::Failed, "Missing proxy discovery state"}};
        conflict |= enabled == "Yes" || automatic == "On";
    }
    return {{}, conflict, active};
}
PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return valid;
    if (auto before = check(config); !before.result.succeeded()) return before.result;
    QStringList names;
    if (auto result = services(runner, names); !result.succeeded()) return result;
    for (const auto &name : names) {
        QList<QStringList> actions;
        for (const auto &type : types) {
            actions.append({"-set" + type, name, "127.0.0.1", QString::number(type == "socksfirewallproxy" ? config.socksPort : config.httpPort), "off"});
            actions.append({"-set" + type + "state", name, "on"});
        }
        actions.append({"-setautoproxystate", name, "off"});
        actions.append({"-setproxyautodiscovery", name, "off"});
        auto bypass = ProxyValidation::bypass(config.bypass);
        QStringList bypassArgs{"-setproxybypassdomains", name};
        bypassArgs.append(bypass.isEmpty() ? QStringList{"Empty"} : bypass);
        actions.append(bypassArgs);
        for (const auto &args : actions) {
            auto result = runner(tool, args).result;
            if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
        }
        // Verify every service and protocol, including disabled endpoints, not just any active proxy.
        for (const auto &type : types) {
            auto command = runner(tool, {"-get" + type, name});
            if (!command.result.succeeded()) { command.result.mayHaveChanged = true; return command.result; }
            const auto data = fields(command.output);
            if (data["Enabled"] != "Yes" || data["Authenticated Proxy Enabled"] != "0" || data["Server"] != "127.0.0.1"
                || data["Port"] != QString::number(type == "socksfirewallproxy" ? config.socksPort : config.httpPort))
                return {Status::Failed, "Proxy endpoint readback mismatch", true};
        }
        auto actual = runner(tool, {"-getproxybypassdomains", name});
        if (!actual.result.succeeded()) { actual.result.mayHaveChanged = true; return actual.result; }
        if (actual.output.isEmpty()) return {Status::Failed, "Missing bypass domain readback", true};
        const auto domains = actual.output.startsWith("There aren't any bypass domains") ? QStringList{} : actual.output.split('\n', Qt::SkipEmptyParts);
        if (domains != bypass) return {Status::Failed, "Proxy bypass readback mismatch", true};
    }
    const auto verified = check(config);
    if (!verified.result.succeeded()) { auto r = verified.result; r.mayHaveChanged = true; return r; }
    if (verified.conflict || !verified.active) return {Status::Failed, "Proxy readback mismatch", true};
    return {Status::Success, {}, true};
}
PlatformOperationResult PlatformSystemProxyBackend::clear() {
    QStringList names;
    if (auto result = services(runner, names); !result.succeeded()) return result;
    for (const auto &name : names) {
        for (const auto &type : types) {
            auto result = runner(tool, {"-set" + type + "state", name, "off"}).result;
            if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
            auto actual = runner(tool, {"-get" + type, name});
            if (!actual.result.succeeded()) { actual.result.mayHaveChanged = true; return actual.result; }
            if (fields(actual.output).value("Enabled") != "No") return {Status::Failed, "Proxy disable readback mismatch", true};
        }
    }
    return {Status::Success, {}, true};
}
