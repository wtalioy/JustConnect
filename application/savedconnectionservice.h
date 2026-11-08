#ifndef SAVEDCONNECTIONSERVICE_H
#define SAVEDCONNECTIONSERVICE_H

#include <QObject>
#include <QStringList>
#include <QVariantMap>

#include <memory>
#include "core/connectionoptions.h"

class SavedConnectionBackend;
class QSettings;

class SavedConnectionService : public QObject
{
    Q_OBJECT

public:
    explicit SavedConnectionService(
        std::unique_ptr<SavedConnectionBackend> backend,
        const QString &overrideConfigPath = {},
        QObject *parent = nullptr
    );
    ~SavedConnectionService() override;

    static ConnectionOptions load(const QSettings &settings);
    static ConnectionOptions load(const QVariantMap &settings);
    static bool validPublicChanges(const QVariantMap &changes);
    static bool writePublic(QSettings &settings,const QVariantMap &changes);
    QSettings *settings() const;
    QString currentConnectionId() const;
    QStringList connections() const;
    bool usesOverrideConfiguration() const;

    bool switchTo(const QString &connectionId);
    QString createAndSwitch(const QString &requestedName);
    bool renameCurrent(const QString &newConnectionId);
    bool removeCurrentAndSwitchToDefault();

    QString normalizeConnectionId(const QString &name) const;
    bool silentStartEnabled() const;
    bool migrateAutoStartSetting(bool enabled);

private:
    bool syncCurrent();
    std::unique_ptr<SavedConnectionBackend> connectionBackend;
    std::unique_ptr<QSettings> currentSettings;
    QString currentId;
    bool overrideConfiguration;
};

#endif // SAVEDCONNECTIONSERVICE_H
