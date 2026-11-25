#pragma once
#include "application/platformoperationresult.h"
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QUuid>
#include <optional>

// Wire contract with the privileged Linux helper (infrastructure/networkhelper/linux).
// Frames are 4-byte big-endian length prefixes around compact UTF-8 JSON, bounded by
// LinuxHelperRequestBytes in both directions. The apply reply additionally carries the
// raw TUN file descriptor via SCM_RIGHTS on the same socket.
inline constexpr int LinuxHelperProtocol = 1;
inline constexpr int LinuxHelperRequestBytes = 65536;
inline constexpr int LinuxHelperOperationTimeoutMs = 30000;
// The polkit password prompt has no natural deadline; keep a generous ceiling.
inline constexpr int LinuxHelperAuthorizationTimeoutMs = 120000;
inline constexpr int LinuxHelperRouteRows = 4096;

// Status strings the helper replies with; they mirror PlatformOperationResult statuses.
inline constexpr const char *LinuxHelperStatusOk = "ok";
inline constexpr const char *LinuxHelperStatusFailed = "failed";
inline constexpr const char *LinuxHelperStatusPermissionDenied = "permission_denied";
inline constexpr const char *LinuxHelperStatusUnsupported = "unsupported";

struct LinuxHelperConfiguration {
    QString address, peer;
    int mtu = 0;
    QStringList capturePrefixes;
    QStringList dnsDomains;
};

struct LinuxHelperDevice {
    QString name;
    int index = 0, mtu = 0;
    QString address, peer;
};

QJsonObject linuxHelperRequest(const char *operation, const QUuid &owner, const QUuid &request);
QJsonObject linuxHelperApplyRequest(const QUuid &owner, const QUuid &request, const LinuxHelperConfiguration &configuration);
QJsonObject linuxHelperExtendRequest(const QUuid &owner, const QUuid &request, const QStringList &addresses);
QJsonObject linuxHelperRoutesRequest(const QUuid &owner, const QUuid &request, const QStringList &prefixes);
bool validLinuxHelperRequest(const QJsonObject &packet);

// Parses one helper reply against its request; the probe reply additionally reports
// the detected DNS mechanism ("resolved", "file", or empty when unknown).
std::optional<PlatformOperationResult> parseLinuxHelperResponse(const QJsonObject &packet, const QJsonObject &request);
QString parseLinuxHelperDnsMode(const QJsonObject &packet);
std::optional<LinuxHelperDevice> parseLinuxHelperDevice(const QJsonObject &packet);
