#include "clashextension.h"
#include "networkprotection.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QStringDecoder>
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
QString extensionFunction(const ConnectionOptions &options, const QString &connectionName, const QJsonObject &resources)
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
    return QStringLiteral(R"JS(function addJustConnect(config) {
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

bool regularFile(const QFileInfo &info)
{
    return info.isFile() && !info.isSymLink() && !info.isJunction();
}

constexpr qint64 maxScriptSize = 4 * 1024 * 1024;

std::optional<QByteArray> readScript(const QString &path)
{
    QFile file(path);
    if (!regularFile(QFileInfo(path)) || !file.open(QIODevice::ReadOnly) || file.size() > maxScriptSize) return {};
    auto contents = file.read(maxScriptSize + 1);
    if (file.error() != QFileDevice::NoError || contents.size() > maxScriptSize) return {};
    return contents;
}

constexpr auto managedStart = "// JustConnect global script integration\nvar main;\n{\n  let __justconnectOriginal;\n  {\n";
constexpr auto originalEnd = "\n    ;__justconnectOriginal = main;\n  }\n";
constexpr auto managedEnd = ";\n}\n// End JustConnect global script integration\n";
constexpr auto wrapper = R"JS(  const __justconnectGlobal = main;
  const __justconnectEntry = function main(config, profileName) {
    globalThis.main = __justconnectGlobal;
    let result;
    try {
      const previous = __justconnectOriginal;
      result = typeof previous === "function" ? previous(config, profileName) : config;
    } finally {
      globalThis.main = __justconnectEntry;
    }
    if (!result || typeof result !== "object" || Array.isArray(result)) return result;
    try {
      const prototype = Object.getPrototypeOf(result);
      if (prototype === Object.prototype || prototype === null) return __justconnectAdd({...result});
    } catch {
      // Keep the user's result if the campus rules cannot be added.
    }
    return result;
  };
  main = __justconnectEntry;
  const __justconnectAdd = )JS";
}

QString ClashExtension::script(const ConnectionOptions &options, const QString &connectionName, const QJsonObject &resources)
{
    const auto extension = extensionFunction(options, connectionName, resources);
    if (extension.isEmpty()) return {};
    return QCoreApplication::translate("ClashExtension",
        "// New script: paste everything.\n"
        "// Already have a script? Paste only the addJustConnect function below,\n"
        "// then add addJustConnect(config); before your main function returns config.\n"
        "// Keep only one main function.")
        + QStringLiteral("\n\nfunction main(config) {\n  return addJustConnect(config);\n}\n\n") + extension;
}

QString ClashExtension::vergeGlobalScriptPath()
{
#ifdef Q_OS_WIN
    const auto data = qEnvironmentVariable("APPDATA");
#else
    const auto data = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
#endif
    if (!QDir::isAbsolutePath(data)) return {};
    const QDir directory(QDir(data).filePath("io.github.clash-verge-rev.clash-verge-rev"));
    if (!regularFile(QFileInfo(directory.filePath("profiles.yaml")))) return {};
    const auto path = directory.filePath("profiles/Script.js");
    return regularFile(QFileInfo(path)) ? path : QString{};
}

ClashExtension::ImportResult ClashExtension::importScript(const QString &path, const ConnectionOptions &options,
    const QString &connectionName, const QJsonObject &resources)
{
    const auto extension = extensionFunction(options, connectionName, resources);
    if (extension.isEmpty() || path.isEmpty()) return ImportResult::Unavailable;
    const auto current = readScript(path);
    if (!current) return ImportResult::FileError;
    QStringDecoder decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless);
    const QString decoded = decoder.decode(*current);
    if (decoder.hasError() || decoded.contains(u'\0')) return ImportResult::Conflict;

    const QByteArray bom = current->startsWith("\xef\xbb\xbf") ? current->first(3) : QByteArray{};
    auto original = current->sliced(bom.size());
    const bool previouslyImported = original.startsWith(managedStart);
    if (previouslyImported) {
        const auto start = QByteArrayView(managedStart).size();
        const auto end = original.indexOf(originalEnd, start);
        if (end < 0 || !original.endsWith(managedEnd)) return ImportResult::Conflict;
        original = original.sliced(start, end - start);
    }
    if (original.contains("JustConnect global script integration") || original.contains("__justconnect"))
        return ImportResult::Conflict;

    const auto updated = bom + managedStart + original + originalEnd + wrapper + extension.toUtf8() + managedEnd;
    if (updated == *current) return ImportResult::Saved;
    if (updated.size() > maxScriptSize) return ImportResult::FileError;

    QSaveFile pending(path);
    if (!pending.open(QIODevice::WriteOnly) || pending.write(updated) != updated.size()) return ImportResult::FileError;
    if (!previouslyImported) {
        const auto backupPath = path + ".justconnect.bak";
        const QFileInfo backupInfo(backupPath);
        if (backupInfo.isSymLink() || backupInfo.isJunction() || (backupInfo.exists() && !backupInfo.isFile()))
            return ImportResult::FileError;
        QSaveFile backup(backupPath);
        if (!backup.open(QIODevice::WriteOnly) || !backup.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)
            || backup.write(*current) != current->size() || !backup.commit())
            return ImportResult::FileError;
    }
    if (readScript(path) != current) return ImportResult::Conflict;
    return pending.commit() ? ImportResult::Saved : ImportResult::FileError;
}
