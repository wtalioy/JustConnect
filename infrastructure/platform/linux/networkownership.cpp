#include "networkownership.h"
#include "iprouteutility.h"
#include <QHostAddress>
#include <QJsonDocument>
#include <QHash>
#include <QMap>
#include <QSet>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

namespace {
QJsonObject route(const QString &prefix, int index, const QString &source, const QString &gateway,
    quint32 table, quint32 metric, int protocol, int scope, int kind = RTN_UNICAST)
{
    QJsonObject row{{"destination", prefix}, {"interface_index", index}};
    for (const auto &[key, value] : QList<QPair<QString, qint64>>{{"table", table}, {"metric", metric},
        {"protocol", protocol}, {"scope", scope}, {"kind", kind}}) if (value) row[key] = value;
    if (!source.isEmpty()) row["source"] = source;
    if (!gateway.isEmpty()) row["gateway"] = gateway;
    return row;
}
QByteArray nativeWord(quint32 value) { return QByteArray(reinterpret_cast<const char *>(&value), sizeof(value)).toHex(); }

bool ownedRule(const QJsonObject &row, quint32 table, const QString &source)
{
    if (row["family"] != AF_INET || row["priority"] != 1 || row["table"].toInteger() != table
        || row["action"] != FR_ACT_TO_TBL || row["flags"] != 0 || row["tos"] != 0
        || row["source"] != source + "/32" || row.contains("destination") || row.size() != 8
        || !row["attributes"].isArray()) return false;
    in_addr address{};
    if (::inet_pton(AF_INET, source.toLatin1().constData(), &address) != 1) return false;
    const QMap<int, QByteArray> expected{{FRA_SRC, QByteArray(reinterpret_cast<const char *>(&address), sizeof(address)).toHex()},
        {FRA_PRIORITY, nativeWord(1)}, {FRA_TABLE, nativeWord(table)}, {FRA_PROTOCOL, QByteArray("04")}};
    QSet<int> found;
    for (const auto &value : row["attributes"].toArray()) {
        const auto attribute = value.toObject();
        const int type = attribute["type"].toInt(-1);
        const auto data = attribute["value_hex"].toString().toLatin1();
        if (!value.isObject() || attribute.size() != 2 || found.contains(type)) return false;
        found.insert(type);
        if (type == FRA_SUPPRESS_PREFIXLEN && data == nativeWord(0xffffffffu)) continue;
        if (!expected.contains(type) || expected[type] != data) return false;
    }
    for (auto key : expected.keys()) if (!found.contains(key)) return false;
    return true;
}
}

NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const QUuid &owner,
    const LinuxHelperConfiguration &configuration, const QJsonObject &device, int originalInterfaceIndex)
{
    const auto name = device["interface"].toString();
    const int index = device["index"].toInt();
    if (owner.isNull() || device["owner"] != owner.toString(QUuid::WithoutBraces)
        || name != QString::fromLatin1(linuxTunName(owner)) || index <= 0 || originalInterfaceIndex <= 0) return {};
    const auto table = linuxSourceTable(owner), metric = linuxRouteMetric(owner);
    QJsonArray routes;
    for (const auto &prefix : configuration.capturePrefixes)
        routes.append(route(prefix, index, configuration.address, configuration.peer, RT_TABLE_MAIN, metric, RTPROT_STATIC, RT_SCOPE_UNIVERSE));
    const auto &sourcePrefixes = configuration.originalPrefixes;
    if (!configuration.originalGateway.isEmpty()) {
        const auto prefix = configuration.originalGateway + "/32";
        routes.append(route(prefix, originalInterfaceIndex, configuration.originalSource, {}, table, metric, RTPROT_STATIC, RT_SCOPE_LINK));
    }
    for (const auto &prefix : sourcePrefixes)
        routes.append(route(prefix, originalInterfaceIndex, configuration.originalSource, configuration.originalGateway,
            table, metric, RTPROT_STATIC, configuration.originalGateway.isEmpty() ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE));
    routes.append(route(configuration.peer + "/32", index, configuration.address, {}, RT_TABLE_MAIN, 0, RTPROT_KERNEL, RT_SCOPE_LINK));
    routes.append(route(configuration.address + "/32", index, configuration.address, {}, RT_TABLE_LOCAL, 0, RTPROT_KERNEL, RT_SCOPE_HOST, RTN_LOCAL));
    QHash<QByteArray, int> ownedRoutes;
    for (const auto &value : routes) ownedRoutes[QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact)] = 1;
    return [configuration, name, index, ownedRoutes, table](QJsonObject network, QJsonObject dns)
        -> std::optional<NetworkPolicySession::OriginalView> {
        if (!network["interfaces"].isArray() || !network["routes"].isArray()) return {};
        QJsonArray interfaces;
        bool identity = false;
        for (const auto &value : network["interfaces"].toArray()) {
            auto row = value.toObject();
            if (row["index"] == index && row["name"] == name && row["up"] == true && row["loopback"] == false) {
                if (identity || !row["addresses"].isArray()) return {};
                identity = true;
                auto addresses = row["addresses"].toArray();
                const auto local = configuration.address + "/32";
                for (int n = addresses.size() - 1; n >= 0; --n) if (addresses[n] == local) addresses.removeAt(n);
                if (addresses.isEmpty()) continue;
                row["addresses"] = addresses;
            }
            interfaces.append(row);
        }
        // A reused index or missing owned interface cannot authorize an exclusion.
        if (!identity) return {};
        network["interfaces"] = interfaces;
        QJsonArray remaining;
        auto expected = ownedRoutes;
        for (const auto &row : network["routes"].toArray()) {
            const auto key = QJsonDocument(row.toObject()).toJson(QJsonDocument::Compact);
            if (expected.value(key) > 0) --expected[key];
            else remaining.append(row);
        }
        network["routes"] = remaining;
        if (network["policy_rules"].isArray()) {
            QJsonArray rules;
            for (const auto &row : network["policy_rules"].toArray())
                if (!ownedRule(row.toObject(), table, configuration.originalSource)) rules.append(row);
            network["policy_rules"] = rules;
        }
        if (!configuration.dnsDomains.isEmpty() && dns["resolved"].isObject()) {
            auto resolved = dns["resolved"].toObject();
            bool linked = false;
            for (const auto &value : resolved["Links"].toArray()) {
                const auto row = value.toObject();
                if (row["interface_index"] != index) continue;
                if (row["name"] != name || linked) return {};
                linked = true;
            }
            if (resolved["status"] != "available" || !linked) return {};
            for (const auto &key : {"DNS", "Domains", "Links"}) {
                if (!resolved.contains(key)) continue;
                if (!resolved[key].isArray()) return {};
                QJsonArray rows;
                for (const auto &value : resolved[key].toArray()) {
                    const auto row = value.toObject();
                    bool owned = false;
                    if (row["interface_index"] == index) {
                        if (QString(key) == "DNS") owned = row.size() == 5 && row["family"] == AF_INET
                            && row["address"] == configuration.peer && (row["port"] == 0 || row["port"] == 53) && row["server_name"] == "";
                        else if (QString(key) == "Domains") owned = row.size() == 3 && row["route_only"] == true
                            && configuration.dnsDomains.contains(row["domain"].toString());
                        else owned = row["name"] == name;
                    }
                    if (!owned) rows.append(value);
                }
                resolved[key] = rows;
            }
            dns["resolved"] = resolved;
        }
        return NetworkPolicySession::OriginalView{network, dns};
    };
}
