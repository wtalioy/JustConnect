#include "clashextension.h"
#include "networkprotection.h"

#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QUrl>
#include <optional>

namespace {
std::optional<QString> target(QString value)
{
    const QHostAddress address(value);
    if (!address.isNull()) {
        if (!address.scopeId().isEmpty() || address.isLoopback()
            || address.isMulticast() || address == QHostAddress::AnyIPv4 || address == QHostAddress::AnyIPv6)
            return {};
        bool ipv4 = false;
        const auto number = address.toIPv4Address(&ipv4);
        // The aTrust data path currently accepts IPv4 destinations only.
        if (!ipv4) return {};
        return QHostAddress(number).toString();
    }
    if (!value.contains('.') || value.startsWith('.') || value.contains('_')) return {};
    return canonicalProtectionName(std::move(value));
}

int appendRules(const ConnectionOptions &options, QJsonArray *rules)
{
    const auto gateway = target(options.endpoint.server);
    const auto signIn = target(options.endpoint.loginDomain);
    const auto lines = options.campusTargets.split('\n');
    QSet<QString> seen;
    for (int i = 0; i < lines.size(); ++i) {
        const auto value = lines[i].trimmed();
        if (value.isEmpty()) continue;
        const auto name = target(value);
        if (!name || name == gateway || name == signIn) return i + 1;
        if (!rules || seen.contains(*name)) continue;
        seen.insert(*name);
        const QHostAddress address(*name);
        if (address.isNull()) rules->append(QJsonArray{"DOMAIN," + *name, ""});
        else rules->append(QJsonArray{"IP-CIDR," + *name + "/32", ",no-resolve"});
    }
    return 0;
}
}

int ClashExtension::invalidTargetLine(const ConnectionOptions &options)
{
    return appendRules(options, nullptr);
}

QString ClashExtension::script(const ConnectionOptions &options)
{
    if (options.routingMode != RoutingMode::LocalProxy) return {};
    const auto endpoint = QUrl::fromEncoded("http://" + options.proxy.socksBind.toLatin1(), QUrl::StrictMode);
    if (endpoint.host() != "127.0.0.1" || endpoint.port() < 1 || !endpoint.userInfo().isEmpty() ||
        !endpoint.path().isEmpty() || endpoint.hasQuery() || endpoint.hasFragment()) return {};
    QJsonArray rules;
    if (appendRules(options, &rules)) return {};
    const QJsonObject settings{{"port", endpoint.port()}, {"rules", rules}};
    return "const campus = " + QString::fromUtf8(QJsonDocument(settings).toJson(QJsonDocument::Compact)) + QStringLiteral(R"JS(;

function main(config) {
  const proxies = config.proxies || [];
  const groups = config["proxy-groups"] || [];
  const rules = config.rules || [];
  const node = {name: "校园网", type: "socks5", server: "127.0.0.1", port: campus.port, udp: true};
  const byName = new Map(proxies.map(proxy => [proxy.name, proxy]));
  const groupNames = new Set(groups.map(group => group.name));
  const fields = Object.keys(node);
  for (let n = 2; byName.has(node.name) || groupNames.has(node.name); n++) {
    const existing = byName.get(node.name);
    if (!groupNames.has(node.name) && existing && Object.keys(existing).length === fields.length &&
        fields.every(key => existing[key] === node[key])) break;
    node.name = "校园网 " + n;
  }
  if (!byName.has(node.name)) config.proxies = proxies.concat(node);
  const existingRules = new Set(rules);
  const added = campus.rules.map(([target, suffix]) => target + "," + node.name + suffix)
    .filter(rule => !existingRules.has(rule));
  if (added.length) config.rules = added.concat(rules);
  return config;
}
)JS");
}
