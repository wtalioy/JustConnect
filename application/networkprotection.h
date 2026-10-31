#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <optional>
#include <utility>

// Separate verified ordinary proxy capture from the original network and resolver view.
std::optional<std::pair<QJsonObject,QJsonObject>> originalProxyNetworkView(QJsonObject network, QJsonObject dns);
// Each target retains references into the original network view.
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
// Read-only DNS ownership planning; overlap coverage must be prepared before capture.
std::optional<QStringList> campusDnsDomains(const QJsonObject &resources);
std::optional<QJsonArray> requiredOriginalDnsNames(const QJsonObject &resources, const QJsonObject &policy);
// A native original listener already dispatches campus choices inside its namespace.
QStringList campusDnsDomainsToInstall(const QStringList &domains,const QJsonArray &originalSources);

// Derive IPv4 capture from resources, confirmed dynamic addresses and protection.
std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy, const QStringList &dynamicAddresses = {}, const QJsonArray &originalDNS = {}, QString *diagnostic = nullptr);

// Withdraw original DNS addresses from the currently owned capture, without adding targets.
std::optional<QStringList> excludeCampusCaptureAddresses(const QStringList &ownedPrefixes, const QStringList &addresses);

// Derive live captures from authoritative resources while validating the owned DNS scope.
std::optional<QStringList> updatedCampusCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const QStringList &dnsDomains, const QJsonArray &originalDNS = {});

// Choose two unused RFC 1918 addresses without overlapping original or campus targets.
std::optional<std::pair<QString, QString>> privateTUNAddresses(const QJsonObject &network, const QStringList &reservedPrefixes);

// Reserve existing resolver literals before allocating a new owned IPv4 pair.
std::optional<QStringList> tunAddressReservations(const QStringList &captures, const QJsonObject &dns, const QString &localDNS);
