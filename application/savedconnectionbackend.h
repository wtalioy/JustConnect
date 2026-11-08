#ifndef SAVEDCONNECTIONBACKEND_H
#define SAVEDCONNECTIONBACKEND_H

#include <QString>
#include <QStringList>

class SavedConnectionBackend
{
public:
    virtual ~SavedConnectionBackend() = default;

    virtual QStringList listConnections() const = 0;
    virtual QString activeConnectionId() const = 0;
    virtual bool setActiveConnection(const QString &connectionId) const = 0;
    virtual QString connectionPath(const QString &connectionId) const = 0;
    virtual QString createConnection(const QString &requestedName) const = 0;
    virtual bool renameConnection(
        const QString &oldId,
        const QString &newId
    ) const = 0;
    virtual bool removeConnection(const QString &connectionId) const = 0;
    virtual QString normalizeConnectionId(const QString &name) const = 0;
    virtual bool silentStartEnabled() const = 0;
    virtual bool setAutoStartEnabled(bool enabled) const = 0;
};

#endif // SAVEDCONNECTIONBACKEND_H
