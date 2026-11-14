#include "clashextension.h"
#include "networkprotection.h"

#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QUrl>
#include <optional>
#include <algorithm>

namespace {
struct PortScope {
    QString protocol;
    int first, last;
};

std::optional<PortScope> portScope(const QJsonObject &resource)
{
    const auto protocol = resource["protocol"].toString();
    const int first = resource["port_min"].toInt(), last = resource["port_max"].toInt();
    if ((protocol != "tcp" && protocol != "udp" && protocol != "all") || first < 1 || last > 65535 || first > last)
        return {};
    return PortScope{protocol, first, last};
}

std::optional<quint64> ipv4(const QString &value)
{
    const QHostAddress address(value);
    if (address.protocol() != QAbstractSocket::IPv4Protocol) return {};
    return address.toIPv4Address();
}

QStringList exportRules(const ConnectionOptions &options, const QJsonObject &resources)
{
    QStringList result, excludedNames;
    QSet<QString> seen;
    QList<std::pair<quint64,quint64>> excludedIPs{{0,0xffffff}, {0x7f000000,0x7fffffff},
        {0xa9fe0000,0xa9feffff}, {0xe0000000,0xffffffff}};
    for (const auto &address : {options.endpoint.server, options.endpoint.loginDomain,
            resources["original_authentication_address"].toString()}) {
        if (const auto number = ipv4(address)) excludedIPs.append({*number,*number});
        else if (const auto name = canonicalProtectionName(address); name && !excludedNames.contains(*name))
            excludedNames.append(*name);
    }
    const auto append = [&](QString target, const PortScope &scope) {
        QStringList conditions;
        if (scope.protocol != "all") conditions.append("NETWORK," + scope.protocol.toUpper());
        if (scope.first != 1 || scope.last != 65535) {
            auto ports = QString::number(scope.first);
            if (scope.last != scope.first) ports += "-" + QString::number(scope.last);
            conditions.append("DST-PORT," + ports);
        }
        conditions.append(std::move(target));
        for (const auto &name : excludedNames) conditions.append("NOT,((DOMAIN," + name + "))");
        auto rule = "AND,((" + conditions.join("),(") + "))";
        if (!seen.contains(rule)) { seen.insert(rule); result.append(std::move(rule)); }
    };
    for (const auto &key : {"domain_resources", "domain_dns_permissions"}) {
        const bool exact = QByteArrayView(key) == "domain_dns_permissions";
        const auto domains = resources[key].toObject();
        for (auto it = domains.begin(); it != domains.end(); ++it) {
            auto host = it.key().trimmed();
            const bool subdomainsOnly = host.startsWith('.');
            if (subdomainsOnly) host.remove(0,1);
            const auto name = canonicalProtectionName(host);
            if (!name || *name == "localhost" || name->endsWith(".localhost") || (exact && excludedNames.contains(*name))) continue;
            QString target = (subdomainsOnly && !exact ? "DOMAIN-SUFFIX," : "DOMAIN,") + *name;
            if (subdomainsOnly) target = "AND,((" + target + "),(NOT,((DOMAIN," + *name + "))))";
            for (const auto &permission : it.value().toArray())
                if (const auto scope = portScope(permission.toObject())) append(target,*scope);
        }
    }
    std::sort(excludedIPs.begin(),excludedIPs.end());
    const auto appendRange = [&](quint64 first, quint64 last, const PortScope &scope) {
        while (first <= last) {
            quint64 span = quint64(1) << 32;
            int bits = 0;
            while (span > last-first+1 || (first & (span-1))) { span >>= 1; ++bits; }
            append("IP-CIDR," + QHostAddress(quint32(first)).toString() + "/" + QString::number(bits) + ",no-resolve",scope);
            first += span;
        }
    };
    for (const auto &entry : resources["ip_resources"].toArray()) {
        const auto resource = entry.toObject();
        const auto min = ipv4(resource["ip_min"].toString()), max = ipv4(resource["ip_max"].toString());
        const auto scope = portScope(resource);
        if (!min || !max || *min > *max || !scope) continue;
        auto first = *min;
        for (const auto &[start,end] : excludedIPs) {
            if (end < first) continue;
            if (start > *max) break;
            if (first < start) appendRange(first,start-1,*scope);
            first = end+1;
        }
        appendRange(first,*max,*scope);
    }
    return result;
}
}

QString ClashExtension::script(const ConnectionOptions &options, const QString &connectionName, const QJsonObject &resources)
{
    if (options.routingMode != RoutingMode::LocalProxy || !resources["domain_resources"].isObject()
        || !resources["ip_resources"].isArray()) return {};
    const auto bind = resources["listeners"].toObject()["socks"].toString();
    const auto endpoint = QUrl::fromEncoded("http://" + bind.toLatin1(), QUrl::StrictMode);
    if (endpoint.host() != "127.0.0.1" || endpoint.port() < 1 || !endpoint.userInfo().isEmpty() ||
        !endpoint.path().isEmpty() || endpoint.hasQuery() || endpoint.hasFragment()) return {};
    const auto rules = exportRules(options,resources);
    auto name = connectionName.simplified();
    name.replace(u',', u'，'); // Mihomo uses commas to separate rule fields.
    if (name.isEmpty()) name = QCoreApplication::translate("ClashExtension", "Campus");
    const auto node = QJsonObject{{"name", name}, {"type", "socks5"}, {"server", endpoint.host()},
        {"port", endpoint.port()}, {"udp", true}};
    QStringList routes;
    for (const auto &rule : rules) {
        auto encoded = QJsonDocument(QJsonArray{rule}).toJson(QJsonDocument::Compact);
        routes.append("    " + QString::fromUtf8(encoded.mid(1,encoded.size()-2)));
    }
    const auto instructions = QCoreApplication::translate("ClashExtension",
        "// New script: paste everything.\n"
        "// Already have a script? Paste only the addJustConnect function below,\n"
        "// then add addJustConnect(config); before your main function returns config.\n"
        "// Keep only one main function.");
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
  const added = campusRoutes.map(rule => rule + "," + node.name)
    .filter(rule => !existingRules.has(rule));
  if (added.length) config.rules = added.concat(originalRules);
  return config;
}
)JS");
}
