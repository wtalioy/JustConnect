#pragma once

#include "infrastructure/platform/platformcommand.h"
#include "infrastructure/platform/tundevice.h"
#include "infrastructure/platform/networkjournal.h"
#include <QJsonArray>
#include <functional>
#include <utility>

struct MacRouteSnapshot { PlatformOperationResult result; QJsonArray rows; };
inline constexpr qsizetype MacRouteSnapshotRows = 4096;
inline constexpr int MacRouteOperationTimeoutMs = 10000;
MacRouteSnapshot readMacRoutes();
QString macRoutePrefix(const QJsonObject &addresses, quint32 flags);
QString macBootSession();

class MacTunRoutes
{
public:
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
    explicit MacTunRoutes(PlatformCommandRunner command = {}) : runner(std::move(command)) {}
    MacTunRoutes(const MacTunRoutes &) = delete;
    MacTunRoutes &operator=(const MacTunRoutes &) = delete;
    PlatformOperationResult apply(const UnixTunDevice &device, const QStringList &prefixes, const CheckpointWriter &checkpoint = {});
    // Failure retains the full ownership record; the caller restores DNS before capture.
    PlatformOperationResult extend(const UnixTunDevice &device, const QStringList &addresses, const CheckpointWriter &checkpoint = {});
    PlatformOperationResult reconcile(const UnixTunDevice &device, const QStringList &prefixes, const CheckpointWriter &checkpoint = {});
    PlatformOperationResult restore(const QUuid &owner, const CheckpointWriter &checkpoint = {});
    // The privileged caller must authenticate the saved record and its connection owner.
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint = {});
    QJsonObject snapshot() const;
    static bool validRecord(const QUuid &owner, const QJsonObject &record);
private:
    bool load(const QUuid &owner, const QJsonObject &record);
    struct Entry { QString prefix; QJsonObject applied; bool deleting = false; };
    PlatformOperationResult append(const QStringList &prefixes, const CheckpointWriter &checkpoint);
    PlatformOperationResult remove(const QStringList &prefixes, const CheckpointWriter &checkpoint);
    PlatformOperationResult save(const CheckpointWriter &checkpoint) const;
    PlatformOperationResult change(const QString &operation, const QString &prefix, int timeoutMs) const;
    bool identity() const;
    bool shape(const QJsonObject &row) const;
    void clear();
    PlatformCommandRunner runner;
    QUuid owner;
    QString interfaceName, boot, sourceAddress, peerAddress;
    quint32 interfaceIndex = 0;
    QList<Entry> entries;
};
