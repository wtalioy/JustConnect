#pragma once

#include "iprouteutility.h"
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <cstring>
#include <linux/fib_rules.h>
#include <sys/socket.h>

// The core attests the controller's network authority and the live kernel TUN identity.
inline std::optional<std::pair<QJsonObject,QJsonObject>> linuxOriginalProxyView(QJsonObject network, QJsonObject dns)
{
    if (!network.contains("proxy_tunnel")) return {{network,dns}};
    const auto identity = network["proxy_tunnel"].toObject();
    const auto index = identity["interface_index"].toInt();
    const auto name = identity["name"].toString();
    if (identity.size() != 2 || index <= 0 || !canonicalLinuxInterfaceName(name)
        || !network["interfaces"].isArray() || !network["routes"].isArray() || !network["policy_rules"].isArray()) return {};
    QJsonArray routes, rules;
    bool found = false;
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (row["index"] != index) continue;
        if (found || row["name"] != name || row["up"] != true || row["loopback"] != false) return {};
        found = true;
    }
    if (!found) return {};
    using Table = QPair<int,qint64>;
    QSet<Table> tables, foreignTables;
    for (const auto &value : network["routes"].toArray()) {
        const auto row = value.toObject();
        const auto subnet = QHostAddress::parseSubnet(row["destination"].toString());
        if (subnet.second < 0) return {};
        const Table table{subnet.first.protocol() == QAbstractSocket::IPv4Protocol ? AF_INET : AF_INET6,row["table"].toInteger()};
        const bool proxy = row["interface_index"] == index && row["next_hops"].toArray().isEmpty();
        if (!proxy) { routes.append(value); foreignTables.insert(table); }
        else if (table.second > RT_TABLE_UNSPEC && table.second != RT_TABLE_DEFAULT
            && table.second != RT_TABLE_MAIN && table.second != RT_TABLE_LOCAL) tables.insert(table);
    }
    // A shared table cannot establish which rules belong to the proxy.
    for (const auto &table : tables) if (foreignTables.contains(table)) return {};
    const auto input = network["policy_rules"].toArray();
    QSet<qsizetype> excluded;
    QMap<int,QPair<qint64,qint64>> priorities;
    for (qsizetype i = 0; i < input.size(); ++i) {
        const auto row = input[i].toObject();
        const int family = row["family"].toInt();
        const auto priority = row["priority"].toInteger();
        if (row["action"] != FR_ACT_TO_TBL || !tables.contains({family,row["table"].toInteger()})) continue;
        if (priority <= LinuxCaptureRulePriority) return {};
        excluded.insert(i);
        if (!priorities.contains(family)) priorities[family] = {priority,priority};
        else { auto &range = priorities[family]; range.first = qMin(range.first,priority); range.second = qMax(range.second,priority); }
    }
    auto attributes = [](const QJsonObject &row) -> std::optional<QMap<int,QByteArray>> {
        if (!row["attributes"].isArray()) return {};
        QMap<int,QByteArray> result;
        for (const auto &value : row["attributes"].toArray()) {
            const auto item = value.toObject();
            const int type = item["type"].toInt(-1);
            const auto hex = item["value_hex"].toString().toLatin1();
            const auto bytes = QByteArray::fromHex(hex);
            if (type < 0 || result.contains(type) || bytes.toHex() != hex) return {};
            result[type] = bytes;
        }
        return result;
    };
    auto number = [](const QByteArray &bytes) -> qint64 {
        if (bytes.size() != sizeof(quint32)) return -1;
        quint32 value; std::memcpy(&value,bytes.constData(),sizeof(value)); return value;
    };
    const QSet<int> common{FRA_TABLE,FRA_PRIORITY,FRA_SUPPRESS_PREFIXLEN,FRA_PROTOCOL};
    for (qsizetype i = 0; i < input.size(); ++i) {
        const auto jump = input[i].toObject();
        const int family = jump["family"].toInt();
        const auto range = priorities.constFind(family);
        const auto priority = jump["priority"].toInteger();
        if (range == priorities.cend() || priority < range->first || priority > range->second
            || jump["action"] != FR_ACT_GOTO || jump["flags"] != 0 || jump["tos"] != 0
            || jump.contains("source") || jump.contains("destination")) continue;
        const auto attrs = attributes(jump);
        if (!attrs || attrs->value(FRA_IIFNAME) != name.toUtf8()+'\0') continue;
        auto allowed = common; allowed.insert(FRA_IIFNAME); allowed.insert(FRA_GOTO);
        bool known = true;
        for (auto it = attrs->cbegin(); it != attrs->cend(); ++it) known &= allowed.contains(it.key());
        const auto target = number(attrs->value(FRA_GOTO));
        if (!known || target <= range->second) continue;
        excluded.insert(i);
        for (qsizetype j = 0; j < input.size(); ++j) {
            const auto row = input[j].toObject();
            if (row["family"] != family || row["tos"] != 0 || row.contains("source") || row.contains("destination")) continue;
            const auto data = attributes(row);
            if (!data || data->value(FRA_PROTOCOL) != attrs->value(FRA_PROTOCOL)) continue;
            auto permitted = common;
            bool linked = row["priority"] == target && row["action"] == FR_ACT_NOP && row["flags"] == 0 && row["table"] == 0;
            // Linux fib_rules.h: FRA_DPORT_MASK is 29, also on kernels with older build headers.
            constexpr int DestinationPortMask = 29;
            if (row["priority"] == priority && row["action"] == FR_ACT_TO_TBL && row["table"].toInteger() == RT_TABLE_MAIN
                && row["flags"] == FIB_RULE_INVERT && number(data->value(FRA_SUPPRESS_PREFIXLEN)) == 0) {
                const quint16 dnsPort = 53;
                const QByteArray ports(reinterpret_cast<const char *>(&dnsPort),sizeof(dnsPort));
                linked = data->value(FRA_DPORT_RANGE) == ports+ports
                    && (!data->contains(DestinationPortMask) || data->value(DestinationPortMask) == QByteArray(2,char(0xff)));
                permitted.insert(FRA_DPORT_RANGE); permitted.insert(DestinationPortMask);
            }
            for (auto it = data->cbegin(); it != data->cend(); ++it) linked &= permitted.contains(it.key());
            if (linked) excluded.insert(j);
        }
    }
    for (qsizetype i = 0; i < input.size(); ++i) if (!excluded.contains(i)) rules.append(input[i]);
    // Keep real interface addresses reserved for device allocation, without granting protection.
    network["routes"] = routes; network["policy_rules"] = rules;
    if (dns["resolved"].isObject()) {
        auto resolved = dns["resolved"].toObject();
        for (const auto *key : {"Links","DNS","Domains"}) {
            if (!resolved.contains(key)) continue;
            if (!resolved[key].isArray()) return {};
            QJsonArray remaining;
            for (const auto &value : resolved[key].toArray())
                if (value.toObject()["interface_index"] != index) remaining.append(value);
            resolved[key] = remaining;
        }
        dns["resolved"] = resolved;
    }
    return {{network,dns}};
}
