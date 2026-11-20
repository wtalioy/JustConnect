#pragma once
#include "infrastructure/networkhelper/linux/networkhelperprotocol.h"
#include <QStringList>
#include <optional>

struct LinuxHelperPreparation {
    PlatformOperationResult result;
    LinuxHelperConfiguration configuration;
};

// Rows proving every policy-required protected name keeps its original
// resolver: one row per required rule with the pre-connection resolvers from
// the host snapshot as its servers. nullopt when a required rule exists but
// the host offers no usable resolver source; an empty `required` list needs
// no rows and returns an empty array.
std::optional<QJsonArray> linuxOriginalDnsSources(const QJsonObject &dns, const QJsonArray &required);

// Plans the privileged capture for one connection. Linux split DNS is
// installed through the helper only: the core answers campus names and
// refuses protected ones, so glibc-class resolvers fall through to the
// original servers. Required rows reserve those servers outside the capture
// and drop the campus scopes they cover from the installed set.
LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &protection,
    const QJsonObject &network, const QJsonObject &dns, const QString &localDNS, int mtu,
    const QStringList &dynamicAddresses = {});

// Re-derives the live capture prefix set from authoritative resources; nullopt
// when the DNS or campus scope drifted and the session must be restored.
std::optional<QStringList> updatedLinuxCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const LinuxHelperConfiguration &configuration, const QJsonObject &network, const QJsonObject &dns);
