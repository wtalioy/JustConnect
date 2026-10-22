#pragma once

#include "application/platformoperationresult.h"
#include <QUuid>

class UnixTunDevice
{
public:
    UnixTunDevice() = default;
    ~UnixTunDevice();
    UnixTunDevice(const UnixTunDevice &) = delete;
    UnixTunDevice &operator=(const UnixTunDevice &) = delete;

    PlatformOperationResult create(const QUuid &owner);
    void close();
    // Borrowed descriptor; SCM_RIGHTS gives the receiver its own reference.
    int descriptor() const { return fd; }
    QString name() const { return interfaceName; }
    quint32 index() const { return interfaceIndex; }
    QUuid owner() const { return ownerId; }
private:
    int fd = -1;
    QString interfaceName;
    quint32 interfaceIndex = 0;
    QUuid ownerId;
};
