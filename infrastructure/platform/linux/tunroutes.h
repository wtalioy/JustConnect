#pragma once

#include "infrastructure/platform/platformcommand.h"
#include "infrastructure/platform/tundevice.h"
#include "iprouteutility.h"
#include <QJsonArray>
#include <QJsonObject>
#include <utility>
#include <functional>

class LinuxTunRoutes
{
public:
    static constexpr qsizetype MaxSnapshotBytes = LinuxRouteRecoveryBytes;
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
    explicit LinuxTunRoutes(PlatformCommandRunner read = {}) : reader(std::move(read)) {}
    LinuxTunRoutes(const LinuxTunRoutes &) = delete;
    LinuxTunRoutes &operator=(const LinuxTunRoutes &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QString &source, const QString &peer, const QStringList &prefixes,
                                  const CheckpointWriter &checkpoint = {});
    PlatformOperationResult restore(const UnixTunDevice &device, const CheckpointWriter &checkpoint = {});
    PlatformOperationResult extend(const UnixTunDevice &device, const QStringList &addresses, const CheckpointWriter &checkpoint = {});
    // The caller must authenticate the privileged owner's saved record before recovery.
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint = {});
    QJsonObject snapshot() const;
private:
    struct Entry { QString prefix; QJsonObject applied; bool deleting = false; };
    struct ReadResult { PlatformOperationResult result; QJsonArray rows; };
    ReadResult read(const QString &utility, int timeoutMs) const;
    bool owns(const UnixTunDevice &device) const;
    bool identity() const;
    QJsonObject find(const QJsonArray &rows, const QString &prefix) const;
    bool createdShape(const QJsonObject &row) const;
    QByteArray command(const QString &operation, const QString &prefix) const;
    PlatformOperationResult saveCheckpoint(const CheckpointWriter &checkpoint) const;
    PlatformOperationResult restore(const QUuid &owner, const CheckpointWriter &checkpoint);
    void clear();
    PlatformCommandRunner reader;
    QUuid owner;
    QString interfaceName, sourceAddress, gatewayPeer, networkNamespace;
    quint32 interfaceIndex = 0, metric = 0;
    QList<Entry> entries;
    enum class Origin { Prepared, Live, Recovered };
    Origin origin = Origin::Prepared;
};
