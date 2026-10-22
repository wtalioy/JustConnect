#pragma once

#include "infrastructure/platform/platformcommand.h"
#include <QDeadlineTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QHash>
#include <QUuid>
#include <utility>

class LinuxSourceRoutes
{
public:
    static constexpr qsizetype MaxSnapshotBytes = 2*1024*1024;
    explicit LinuxSourceRoutes(PlatformCommandRunner read = {}) : reader(std::move(read)) {}
    LinuxSourceRoutes(const LinuxSourceRoutes &) = delete;
    LinuxSourceRoutes &operator=(const LinuxSourceRoutes &) = delete;
    PlatformOperationResult apply(const QUuid &owner, const QString &interface, const QString &source,
                                  const QString &gateway, const QStringList &prefixes);
    PlatformOperationResult restore(const QUuid &owner);
    // The caller must authenticate the privileged owner's saved record before recovery.
    PlatformOperationResult recover(const QUuid &owner, const QJsonObject &saved);
    QJsonObject snapshot() const;
private:
    struct Entry { QString prefix; QJsonObject applied; };
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
    void clear();
    PlatformCommandRunner reader;
    QUuid owner;
    QString interfaceName, sourceAddress, gatewayAddress, networkNamespace;
    quint32 interfaceIndex = 0, table = 0, metric = 0;
    QList<Entry> entries;
    bool rulePending = false;
    QJsonObject appliedRule;
};
