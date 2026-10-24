#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <optional>

// Each target retains references into the unchanged native network snapshot.
std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network);
// Known address overlaps explain conflicts; they never grant campus authorization.
std::optional<QJsonArray> campusProtectionConflicts(const QJsonArray &targets, const QJsonObject &resources);
// Native namespace expressions retain their role and source; they do not grant authorization.
std::optional<QJsonArray> originalDnsNamespaces(const QJsonObject &dns);
// Rules retain native namespace references; this model does not apply a policy.
std::optional<QJsonObject> originalDnsProtection(const QJsonObject &dns);
std::optional<QString> canonicalProtectionName(QString name);
QJsonObject protectionConfiguration(const QJsonArray &targets, const QJsonArray &names);

struct CampusCaptureTargets {
    QStringList ipv4Prefixes;
    QStringList dnsDomains;
};
// Derive initial IPv4 capture from parsed resources and the core-confirmed policy.
std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy);
