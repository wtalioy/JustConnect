#pragma once

#include "application/platformoperationresult.h"
#include <QJsonObject>
#include <QUuid>
#include <sys/types.h>

// One bounded JSON packet per operation; only a successful apply carries one TUN fd.
inline constexpr int LinuxHelperProtocol = 1;
inline constexpr int LinuxHelperPacketBytes = 65536;
PlatformOperationResult sendLinuxHelperPacket(int socket, const QJsonObject &packet, int descriptor = -1);
PlatformOperationResult receiveLinuxHelperPacket(int socket, QJsonObject &packet, int &descriptor, int timeoutMs);
QByteArray linuxHelperSocketName(uid_t uid, const QUuid &owner);
int connectLinuxHelper(uid_t uid, const QUuid &owner);
// The connected OS peer, not request fields, determines the authorized account/process.
int runLinuxNetworkHelper(int socket, int trustedDirectory, uid_t uid, pid_t pid, const QUuid &owner);
