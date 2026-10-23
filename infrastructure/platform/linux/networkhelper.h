#pragma once

#include "application/platformoperationresult.h"
#include <QJsonObject>
#include <QUuid>
#include <QStringList>
#include <optional>
#include <functional>
#include <sys/types.h>

// One bounded JSON packet per operation; only a successful apply carries one TUN fd.
inline constexpr int LinuxHelperProtocol = 2;
// Exit 0 confirms receipt removal; exit 2 retains a completed receipt for a later caller.
inline constexpr int LinuxHelperReceiptRetained = 2;
inline constexpr int LinuxHelperPacketBytes = 65536;
inline constexpr int LinuxHelperPacketTimeoutMs = 5000;
// Bound one recovery pass over privileged storage; excess records are reported, never silently omitted.
inline constexpr int LinuxHelperRecoveryEntries = 4096;
struct LinuxHelperRecoverySummary {
    int checked = 0, live = 0, restored = 0, unchanged = 0, failed = 0;
    bool limited = false;
    bool succeeded() const { return failed == 0 && !limited; }
    QJsonObject json() const;
};
// No caller-supplied recovery JSON or path: callers provide the already authenticated private root directory.
LinuxHelperRecoverySummary recoverLinuxHelperRecords(int trustedDirectory);
struct LinuxHelperConfiguration {
    QString address, peer;
    int mtu = 0;
    QStringList capturePrefixes;
    QString originalInterface, originalSource, originalGateway;
    QStringList originalPrefixes;
};
QJsonObject linuxHelperApplyRequest(const QUuid &owner, const LinuxHelperConfiguration &config);
std::optional<LinuxHelperConfiguration> parseLinuxHelperApply(const QUuid &owner, const QJsonObject &request);
PlatformOperationResult sendLinuxHelperPacket(int socket, const QJsonObject &packet, int descriptor = -1, int timeoutMs = LinuxHelperPacketTimeoutMs);
PlatformOperationResult receiveLinuxHelperPacket(int socket, QJsonObject &packet, int &descriptor, int timeoutMs);
QByteArray linuxHelperSocketName(uid_t uid, const QUuid &owner);
int connectLinuxHelper(uid_t uid, const QUuid &owner);
// The connected OS peer, not request fields, determines the authorized account/process.
int runLinuxNetworkHelper(int socket, int trustedDirectory, uid_t uid, pid_t pid, const QUuid &owner,
    const std::function<PlatformOperationResult()> &beforeApply = {});
PlatformOperationResult linuxNetworkRecoveryReady();
