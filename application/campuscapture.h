#pragma once

#include "application/platformoperationresult.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <optional>
#include <utility>

struct CampusCaptureTargets {
    QStringList ipv4Prefixes;
    QStringList dnsDomains;
    QStringList reservedPrefixes;
    bool privateFallback = false;
};
struct CampusTunCapture {
    PlatformOperationResult result;
    QString address, peer;
    QStringList prefixes;
};
// Read-only DNS ownership planning; overlap coverage must be prepared before capture.
std::optional<QStringList> campusDnsDomains(const QJsonObject &resources);
std::optional<QStringList> domainDnsOverrideNames(const QJsonObject &resources);
std::optional<QJsonArray> requiredOriginalDnsNames(const QJsonObject &resources, const QJsonObject &policy);
// A native original listener already dispatches campus choices inside its namespace.
QStringList campusDnsDomainsToInstall(const QStringList &domains,const QJsonArray &originalSources);

// Derive IPv4 capture from resources, confirmed dynamic addresses and protection.
std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy, const QStringList &dynamicAddresses = {}, const QJsonArray &originalDNS = {}, QString *diagnostic = nullptr);
CampusTunCapture prepareCampusTunCapture(const CampusCaptureTargets &targets,
    const QJsonObject &network, const QJsonObject &dns, const QString &localDNS);

// Withdraw original DNS addresses from the currently owned capture, without adding targets.
std::optional<QStringList> excludeCampusCaptureAddresses(const QStringList &ownedPrefixes, const QStringList &addresses);

// Derive live captures from authoritative resources while validating the owned DNS scope.
std::optional<QStringList> updatedCampusCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const QStringList &dnsDomains, const QJsonArray &originalDNS = {}, const QStringList &deviceAddresses = {});

// Choose two unused RFC 1918 addresses without overlapping original or campus targets.
std::optional<std::pair<QString, QString>> privateTUNAddresses(const QJsonObject &network, const QStringList &reservedPrefixes);

// Reserve existing resolver literals before allocating a new owned IPv4 pair.
std::optional<QStringList> tunAddressReservations(const QStringList &captures, const QJsonObject &dns, const QString &localDNS);
