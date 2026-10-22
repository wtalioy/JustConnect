#pragma once

#include "infrastructure/platform/platformcommand.h"
#include "infrastructure/platform/tundevice.h"
#include <QJsonArray>
#include <QJsonObject>
#include <utility>

class LinuxTunRoutes
{
public:
    explicit LinuxTunRoutes(PlatformCommandRunner read = {}) : reader(std::move(read)) {}
    LinuxTunRoutes(const LinuxTunRoutes &) = delete;
    LinuxTunRoutes &operator=(const LinuxTunRoutes &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QString &source, const QString &peer, const QStringList &prefixes);
    PlatformOperationResult restore(const UnixTunDevice &device);
    QJsonObject snapshot() const;
private:
    struct Entry { QString prefix; QJsonObject applied; };
    struct ReadResult { PlatformOperationResult result; QJsonArray rows; };
    ReadResult read(const QString &utility, int timeoutMs) const;
    bool owns(const UnixTunDevice &device) const;
    QJsonObject find(const QJsonArray &rows, const QString &prefix) const;
    bool createdShape(const QJsonObject &row) const;
    QByteArray command(const QString &operation, const QString &prefix) const;
    void clear();
    PlatformCommandRunner reader;
    QUuid owner;
    QString interfaceName, sourceAddress, gatewayPeer;
    quint32 interfaceIndex = 0, metric = 0;
    QList<Entry> entries;
};
