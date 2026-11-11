#ifndef SAVEDCONNECTIONSTORE_H
#define SAVEDCONNECTIONSTORE_H

#include <QString>
#include <QStringList>

#include "application/savedconnectionbackend.h"

class SavedConnectionStore : public SavedConnectionBackend
{
public:
    explicit SavedConnectionStore(const QString &storageRoot = {});

    QStringList listConnections() const override;

    QString activeConnectionId() const override;

    bool setActiveConnection(const QString &connectionId) const override;

    QString connectionPath(const QString &connectionId) const override;

    QString createConnection(const QString &requestedName,const QString &draftPath={}) const override;

    bool renameConnection(const QString &oldId, const QString &newId) const override;

    bool removeConnection(const QString &connectionId) const override;

    QString normalizeConnectionId(const QString &name) const override;

    bool autoStartEnabled() const;

    bool setAutoStartEnabled(bool enabled) const override;

    bool silentStartEnabled() const override;

    bool setSilentStartEnabled(bool enabled) const;
    QString language() const;
    static bool supportsLanguage(const QString &language);
    bool setApplicationPreferences(const QString &language, bool closeToTray) const;
    QString controllerAddress() const;
    bool setControllerAddress(const QString &address) const;
    bool closeToTray() const;
    bool setCloseToTray(bool enabled) const;

private:
    QString configRootPath;
    QString connectionsPath;
    QString statePath;
    QString defaultConnectionPath;

    QString ensureUniqueConnectionId(const QString &baseId) const;

    void ensureStorage() const;
};

#endif //SAVEDCONNECTIONSTORE_H
