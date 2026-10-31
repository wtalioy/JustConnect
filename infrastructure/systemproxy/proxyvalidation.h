#pragma once
#include "application/systemproxybackend.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHostAddress>
#include <QSet>
#include <QUrl>
#include <optional>
#include <algorithm>

namespace ProxyValidation {
inline QString localEndpoint(QString host, int port) {
    if (host == "localhost") host = "127.0.0.1";
    const QHostAddress ip(host);
    if (!ip.isLoopback() || port < 1 || port > 65535) return {};
    return (ip.protocol() == QAbstractSocket::IPv6Protocol ? '[' + ip.toString() + ']' : ip.toString())
        + ':' + QString::number(port);
}
inline QString endpoint(const QString &value) {
    const QUrl url(value.contains("://") ? value : "socks://" + value);
    if (!url.isValid() || !url.userInfo().isEmpty() || !url.path().isEmpty()
        || url.hasQuery() || url.hasFragment()) return {};
    return localEndpoint(url.host(), url.port());
}
inline bool matches(const QStringList &expected, const QStringList &actual) {
    return !actual.isEmpty() && std::all_of(actual.begin(), actual.end(), [&](const QString &value) { return expected.contains(value); });
}
inline PlatformOperationResult config(const SystemProxyConfig &config) {
    if (config.httpPort < 1 || config.httpPort > 65535 || config.socksPort < 1 || config.socksPort > 65535
        || config.bypass.contains('\n') || config.bypass.contains('\r') || config.bypass.contains(QChar('\0')))
        return {PlatformOperationResult::Status::Failed, "Invalid proxy ports or bypass list"};
    QSet<QString> seen;
    for (const auto &value : config.upstream) {
        if (value.isEmpty() || endpoint(value) != value || seen.contains(value))
            return {PlatformOperationResult::Status::Failed, "Invalid upstream proxy identity"};
        seen.insert(value);
    }
    return {};
}
inline QJsonObject json(const SystemProxyConfig &config) {
    QJsonObject result{{"http_port",config.httpPort},{"socks_port",config.socksPort},{"bypass",config.bypass}};
    if (!config.upstream.isEmpty()) result["upstream"] = QJsonArray::fromStringList(config.upstream);
    return result;
}
inline std::optional<SystemProxyConfig> parse(const QJsonObject &value) {
    const auto http=value["http_port"].toInteger(-1), socks=value["socks_port"].toInteger(-1);
    if ((value.size()!=3 && value.size()!=4) || http<1 || http>65535 || socks<1 || socks>65535
        || !value["bypass"].isString() || (value.size()==4 && !value["upstream"].isArray())) return {};
    SystemProxyConfig result{int(http),int(socks),value["bypass"].toString()};
    if (value.contains("upstream")) {
        for (const auto &entry : value["upstream"].toArray()) {
            if (!entry.isString()) return {};
            result.upstream.append(entry.toString());
        }
        if (result.upstream.isEmpty()) return {};
    }
    if (!config(result).succeeded()) return {};
    return result;
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
