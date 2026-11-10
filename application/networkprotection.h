#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <optional>

// Separate verified ordinary proxy routes from the original network view.
std::optional<QJsonObject> originalProxyNetworkView(QJsonObject network);
// Targets refer to indices in the already projected original network view.
std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network);
// Known address overlaps explain conflicts; they never grant campus authorization.
std::optional<QJsonArray> campusProtectionConflicts(const QJsonArray &targets, const QJsonObject &resources);
// Native namespace expressions retain their role and source; they do not grant authorization.
std::optional<QJsonArray> originalDnsNamespaces(const QJsonObject &dns);
// Rules retain native namespace references; this model does not apply a policy.
std::optional<QJsonObject> originalDnsProtection(const QJsonObject &dns);
std::optional<QString> canonicalProtectionName(QString name);
QJsonObject protectionConfiguration(const QJsonArray &targets, const QJsonArray &names);
