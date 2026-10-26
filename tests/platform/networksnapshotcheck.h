#pragma once
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
}
