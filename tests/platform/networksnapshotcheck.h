#pragma once
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>

namespace NetworkSnapshotCheck {
inline QJsonObject difference(const QJsonObject &before,const QJsonObject &after)
{
    QJsonObject changed;
    auto keys=before.keys();keys.append(after.keys());keys.removeDuplicates();
    for(const auto &key:keys)if(before[key]!=after[key])
        changed[key]=QJsonObject{{"before",before[key]},{"after",after[key]}};
    return changed;
}

inline QString protectionMismatch(const QJsonArray &before,const QJsonArray &after,
                                  const QJsonObject &originalNetwork,const QJsonArray &campusAddresses)
{
    for(const auto &prefix:before)
        if(!after.contains(prefix))return QString("missing original protection: %1").arg(prefix.toString());
    QList<QPair<QHostAddress,int>> origins;
    const auto add=[&](const QString &text){
        const auto prefix=QHostAddress::parseSubnet(text);
        if(!prefix.first.isNull() && prefix.second>1)origins.append(prefix);
    };
    for(const auto &entry:originalNetwork["interfaces"].toArray())
        for(const auto &address:entry.toObject()["addresses"].toArray())add(address.toString());
    for(const auto &entry:originalNetwork["routes"].toArray())add(entry.toObject()["destination"].toString());
    for(const auto &value:after){
        if(before.contains(value))continue;
        const auto added=QHostAddress::parseSubnet(value.toString());
        if(added.first.isNull() || added.second<=1)return "invalid additional protection";
        for(const auto &value:campusAddresses){
            const QHostAddress address(value.toString());
            if(address.isNull())return "invalid published campus address";
            if(address.isInSubnet(added))return QString("campus capture leaked into original protection: %1").arg(value.toString());
        }
        bool native=false;
        for(const auto &origin:origins)
            native|=added.second>=origin.second && added.first.isInSubnet(origin);
        if(!native)return QString("additional protection has no native source: %1").arg(value.toString());
    }
    return {};
}
}
