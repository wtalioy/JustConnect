#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <optional>
#include <utility>

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
// Derive IPv4 capture from resources, confirmed dynamic addresses and protection.
std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy, const QStringList &dynamicAddresses = {});

// Choose two unused RFC 1918 addresses without overlapping original or campus targets.
std::optional<std::pair<QString, QString>> privateTUNAddresses(const QJsonObject &network, const QStringList &reservedPrefixes);

// Reserve existing resolver literals before allocating a new owned IPv4 pair.
std::optional<QStringList> tunAddressReservations(const QStringList &captures, const QJsonObject &dns, const QString &localDNS);
