#pragma once

#include "infrastructure/platform/platformcommand.h"
#include "iprouteutility.h"
#include <QDeadlineTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QHash>
#include <QUuid>
#include <functional>
#include <utility>

class LinuxSourceRoutes
{
public:
    static constexpr qsizetype MaxSnapshotBytes = LinuxRouteRecoveryBytes;
    // An empty record requests durable removal after all owned kernel state is gone.
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
    explicit LinuxSourceRoutes(PlatformCommandRunner read = {}) : reader(std::move(read)) {}
    static PlatformOperationResult validate(const QString &interface, const QString &source, const QString &gateway, const QStringList &prefixes);
    LinuxSourceRoutes(const LinuxSourceRoutes &) = delete;
    LinuxSourceRoutes &operator=(const LinuxSourceRoutes &) = delete;
    PlatformOperationResult apply(const QUuid &owner, const QString &interface, const QString &source,
                                  const QString &gateway, const QStringList &prefixes,
                                  const CheckpointWriter &writeAhead = {});
    PlatformOperationResult restore(const QUuid &owner, const CheckpointWriter &checkpoint = {});
    // Adds DNS addresses in place; a failed native write retains ownership for ordered restoration.
    PlatformOperationResult extend(const QUuid &owner, const QStringList &addresses, const CheckpointWriter &checkpoint = {});
    // The caller must authenticate the privileged owner's saved record before recovery.
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint = {});
    QJsonObject snapshot() const;
private:
    struct Entry { QString prefix; QJsonObject applied; bool deleting = false; };
    struct ReadResult { PlatformOperationResult result; QJsonArray routes, rules; QHash<QString,QJsonObject> ownedRoutes; };
    ReadResult read(const QString &utility, const QDeadlineTimer &deadline) const;
    bool identity() const;
    bool sourceAssigned() const;
    bool routeShape(const QJsonObject &row, const QString &prefix) const;
    bool ruleShape(const QJsonObject &row) const;
    QJsonObject findRoute(const ReadResult &rows, const QString &prefix) const;
    QJsonObject findRule(const QJsonArray &rows) const;
    QByteArray routeCommand(const QString &operation, const QString &prefix) const;
    QByteArray ruleCommand(const QString &operation) const;
    PlatformOperationResult saveCheckpoint(const CheckpointWriter &writer) const;
    void clear();
    PlatformCommandRunner reader;
    QUuid owner;
    QString interfaceName, sourceAddress, gatewayAddress, networkNamespace;
    quint32 interfaceIndex = 0, table = 0, metric = 0;
    QList<Entry> entries;
    bool rulePending = false;
    bool ruleDeleting = false;
    QJsonObject appliedRule;
};
