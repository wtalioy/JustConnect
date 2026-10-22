#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <optional>

// Each target retains references into the unchanged native network snapshot.
std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network);
// Known address overlaps explain conflicts; they never grant campus authorization.
std::optional<QJsonArray> campusProtectionConflicts(const QJsonArray &targets, const QJsonObject &resources);
// Native namespace expressions retain their role and source; they do not grant authorization.
std::optional<QJsonArray> originalDnsNamespaces(const QJsonObject &dns);
