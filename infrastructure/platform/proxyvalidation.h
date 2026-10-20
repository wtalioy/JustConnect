#pragma once
#include "application/systemproxybackend.h"
#include <QJsonArray>
#include <QJsonDocument>

namespace ProxyValidation {
inline PlatformOperationResult config(const SystemProxyConfig &config) {
    if (config.httpPort < 1 || config.httpPort > 65535 || config.socksPort < 1 || config.socksPort > 65535
        || config.bypass.contains('\n') || config.bypass.contains('\r') || config.bypass.contains(QChar('\0')))
        return {PlatformOperationResult::Status::Failed, "Invalid proxy ports or bypass list"};
    return {};
}
inline QStringList bypass(const QString &value) {
    QStringList result;
    for (const auto &entry : value.split(';', Qt::SkipEmptyParts)) {
        const auto trimmed = entry.trimmed();
        if (!trimmed.isEmpty() && !result.contains(trimmed)) result.append(trimmed);
    }
    return result;
}
inline QString listValue(const QStringList &items) {
    QJsonArray array;
    for (const auto &item : items) array.append(item);
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
}
}
