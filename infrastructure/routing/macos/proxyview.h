#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QRegularExpression>
#include <optional>

// Only the attested controller's live utun is an alternate exit, not an original network.
inline std::optional<QJsonObject> macOriginalProxyView(QJsonObject network)
{
    if (!network.contains("proxy_tunnel")) return network;
    const auto identity = network["proxy_tunnel"].toObject();
    const auto index = identity["interface_index"].toInteger();
    static const QRegularExpression name("\\Autun[0-9]+\\z");
    if (identity.size() != 2 || index <= 0 || identity["interface_index"] != index
        || !name.match(identity["name"].toString()).hasMatch()
        || !network["interfaces"].isArray() || !network["routes"].isArray()) return {};
    bool found = false;
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (row["index"] != index) continue;
        if (found || row["name"] != identity["name"] || row["up"] != true || row["loopback"] != false) return {};
        found = true;
    }
    if (!found) return {};
    QJsonArray routes;
    for (const auto &value : network["routes"].toArray()) {
        const auto row = value.toObject();
        if (row["interface_index"] != index) routes.append(value);
    }
    // Retain addresses for collision-free allocation.
    network["routes"] = routes;
    return network;
}
