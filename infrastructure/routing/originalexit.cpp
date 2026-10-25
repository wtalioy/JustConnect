#include "infrastructure/routing/originalexit.h"
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QSet>

std::optional<QJsonObject> originalExitSnapshot(const QJsonObject &network,const QString &preferred)
{
    if (!network["interfaces"].isArray() || !network["routes"].isArray()) return {};
    QSet<int> indexes;
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (!preferred.isEmpty() && row["name"] == preferred && row["up"] == true) indexes.insert(row["index"].toInt());
    }
    if (!preferred.isEmpty() && indexes.isEmpty()) return {};
    QMap<QByteArray,QJsonObject> routes;
    for (const auto &value : network["routes"].toArray()) {
        auto row = value.toObject();
        const auto subnet = QHostAddress::parseSubnet(row["destination"].toString());
        if (subnet.second < 0 || subnet.second > 1 || (!preferred.isEmpty() && !indexes.contains(row["interface_index"].toInt()))) continue;
        routes[QJsonDocument(row).toJson(QJsonDocument::Compact)] = row;
        indexes.insert(row["interface_index"].toInt());
    }
    QMap<QString,QJsonObject> interfaces;
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (!indexes.contains(row["index"].toInt())) continue;
        if (row["up"] != true || !row["addresses"].isArray()) return {};
        QStringList addresses;
        for (const auto &address : row["addresses"].toArray()) addresses.append(address.toString());
        addresses.sort();
        interfaces[row["name"].toString()] = {{"name",row["name"]},{"index",row["index"]},{"addresses",QJsonArray::fromStringList(addresses)}};
    }
    QJsonArray routeRows, interfaceRows;
    for (const auto &row : routes) routeRows.append(row);
    for (const auto &row : interfaces) interfaceRows.append(row);
    return QJsonObject{{"interfaces",interfaceRows},{"routes",routeRows}};
}
