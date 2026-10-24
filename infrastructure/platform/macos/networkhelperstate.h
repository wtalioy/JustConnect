#pragma once

#include "networkhelper.h"
#include "tunroutes.h"
#include "tundns.h"
#include <sys/types.h>

class MacNetworkHelperState
{
public:
    ~MacNetworkHelperState();
    PlatformOperationResult open(int bootDirectory, uid_t uid, const QUuid &owner, bool create);
    PlatformOperationResult apply(const MacHelperConfiguration &configuration);
    PlatformOperationResult restore();
    PlatformOperationResult cleanup();
    QString phase() const { return metadata["phase"].toString("unknown"); }
    QUuid owner() const { return connection; }
    uid_t uid() const { return user; }
    int descriptor() const { return device.descriptor(); }
    QJsonObject deviceInfo() const { return device.snapshot(); }
private:
    PlatformOperationResult commit(const QJsonObject &record);
    PlatformOperationResult store(const QString &phase);
    bool valid(const QJsonObject &record) const;
    bool deviceAbsent() const;
    PlatformOperationResult removeDirectory();
    uid_t user = 0;
    QUuid connection;
    QJsonObject metadata;
    int userDirectory = -1, directory = -1, captureDirectory = -1;
    UnixNetworkJournal guardian, captureJournal;
    UnixTunDevice device;
    MacTunRoutes capture;
    MacTunDns dns;
};

// The daemon scopes all callers to the current kernel boot, independently of request data.
int openMacHelperBootDirectory();
