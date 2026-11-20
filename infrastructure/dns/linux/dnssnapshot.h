#pragma once
#include "infrastructure/dns/dnssnapshot.h"

#include <QJsonObject>
#include <optional>

inline constexpr qsizetype LinuxDnsSnapshotBytes = 262144;

// Reads /etc/resolv.conf (with systemd-resolved upstreams behind a stub listener).
DnsSnapshot readLinuxDnsSnapshot();

// Parses the per-link sections of `resolvectl status`; exported for tests,
// which replay recorded desktop output.
std::optional<QJsonObject> parseResolvedPerLinkStatus(const QString &status);
