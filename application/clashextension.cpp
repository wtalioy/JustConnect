#include "clashextension.h"
#include "networkprotection.h"

#include <QCoreApplication>
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

QString ClashExtension::script(const ConnectionOptions &options, const QString &connectionName)
{
    if (options.routingMode != RoutingMode::LocalProxy) return {};
    const auto endpoint = QUrl::fromEncoded("http://" + options.proxy.socksBind.toLatin1(), QUrl::StrictMode);
    if (endpoint.host() != "127.0.0.1" || endpoint.port() < 1 || !endpoint.userInfo().isEmpty() ||
        !endpoint.path().isEmpty() || endpoint.hasQuery() || endpoint.hasFragment()) return {};
    QJsonArray rules;
    if (appendRules(options, &rules)) return {};
    auto name = connectionName.simplified();
    name.replace(u',', u'，'); // Mihomo uses commas to separate rule fields.
    if (name.isEmpty()) name = QCoreApplication::translate("ClashExtension", "Campus");
    const auto node = QJsonObject{{"name", name}, {"type", "socks5"}, {"server", endpoint.host()},
        {"port", endpoint.port()}, {"udp", true}};
    QStringList routes;
    for (const auto &rule : rules)
        routes.append("    " + QString::fromUtf8(QJsonDocument(rule.toArray()).toJson(QJsonDocument::Compact)));
    const auto instructions = QCoreApplication::translate("ClashExtension",
        "// New script: paste everything.\n"
        "// Already have a script? Paste only the addJustConnect function below,\n"
        "// then add addJustConnect(config); before your main function returns config.\n"
        "// Keep only one main function. Replace any older JustConnect block.");
    return instructions + QStringLiteral(R"JS(

function main(config) {
  return addJustConnect(config);
}

function addJustConnect(config) {
  const node = )JS") + QString::fromUtf8(QJsonDocument(node).toJson(QJsonDocument::Compact))
    + QStringLiteral(";\n  const campusRoutes = [\n") + routes.join(",\n") + QStringLiteral(R"JS(
  ];

  const proxies = config.proxies || [];
  const originalRules = config.rules || [];
  const baseName = node.name;
  const byName = new Map(proxies.map(proxy => [proxy.name, proxy]));
  const occupied = new Set(["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL"]);
  for (const group of config["proxy-groups"] || []) occupied.add(group.name);
  const fields = Object.keys(node);
  for (let n = 2; byName.has(node.name) || occupied.has(node.name); n++) {
    const existing = byName.get(node.name);
    if (!occupied.has(node.name) && existing && Object.keys(existing).length === fields.length &&
        fields.every(key => existing[key] === node[key])) break;
    node.name = baseName + " " + n;
  }
  if (!byName.has(node.name)) config.proxies = proxies.concat(node);
  const existingRules = new Set(originalRules);
  const added = campusRoutes.map(([target, suffix]) => target + "," + node.name + suffix)
    .filter(rule => !existingRules.has(rule));
  if (added.length) config.rules = added.concat(originalRules);
  return config;
}
)JS");
}
