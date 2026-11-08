#include "savedconnectionservice.h"

#include <QFileInfo>
#include <QSettings>

#include <utility>

#include "application/savedconnectionbackend.h"
#include "application/defaultsettings.h"
#include "application/settingsmigrator.h"

namespace {
std::unique_ptr<QSettings> readableSettings(const QString &path)
{
    if (!SettingsMigrator::readableFile(path)) return {};
    auto settings = std::make_unique<QSettings>(path, QSettings::IniFormat);
    settings->sync();
    if (settings->status() != QSettings::NoError) return {};
    return settings;
}
}

SavedConnectionService::SavedConnectionService(
    std::unique_ptr<SavedConnectionBackend> backend,
    const QString &overrideConfigPath,
    QObject *parent
)
    : QObject(parent),
      connectionBackend(std::move(backend)),
      overrideConfiguration(!overrideConfigPath.isEmpty())
{
    if (!overrideConfiguration)
    {
        currentId = connectionBackend->activeConnectionId();
        currentSettings = std::make_unique<QSettings>(
            connectionBackend->connectionPath(currentId),
            QSettings::IniFormat
        );
    }
    else
    {
        currentId = "custom";
        currentSettings = std::make_unique<QSettings>(overrideConfigPath, QSettings::IniFormat);
    }
}

SavedConnectionService::~SavedConnectionService()
{
    currentSettings->sync();
}

QSettings *SavedConnectionService::settings() const
{
    return currentSettings.get();
}

QString SavedConnectionService::currentConnectionId() const
{
    return currentId;
}

QStringList SavedConnectionService::connections() const
{
    return connectionBackend->listConnections();
}

bool SavedConnectionService::usesOverrideConfiguration() const
{
    return overrideConfiguration;
}

bool SavedConnectionService::switchTo(const QString &connectionId)
{
    if (!overrideConfiguration && connectionId == currentId)
    {
        return true;
    }

    auto next = readableSettings(connectionBackend->connectionPath(connectionId));
    if (!next || !syncCurrent()) return false;
    if (!connectionBackend->setActiveConnection(connectionId))
    {
        return false;
    }

    currentSettings = std::move(next);
    currentId = connectionId;
    overrideConfiguration = false;
    return true;
}

QString SavedConnectionService::createAndSwitch(const QString &requestedName)
{
    if (!syncCurrent()) return {};
    const QString connectionId = connectionBackend->createConnection(requestedName);
    if (connectionId.isEmpty() || !switchTo(connectionId))
    {
        if (!connectionId.isEmpty())
        {
            connectionBackend->removeConnection(connectionId);
        }
        return {};
    }
    return connectionId;
}

bool SavedConnectionService::renameCurrent(const QString &newConnectionId)
{
    if (currentId.isEmpty() || overrideConfiguration)
    {
        return false;
    }

    if (!syncCurrent()) return false;
    if (!connectionBackend->renameConnection(currentId, newConnectionId))
    {
        return false;
    }

    const QString previousId = currentId;
    if (!connectionBackend->setActiveConnection(newConnectionId))
    {
        connectionBackend->renameConnection(newConnectionId, previousId);
        return false;
    }

    currentId = newConnectionId;
    currentSettings = std::make_unique<QSettings>(
        connectionBackend->connectionPath(currentId),
        QSettings::IniFormat
    );
    return true;
}

bool SavedConnectionService::removeCurrentAndSwitchToDefault()
{
    if (currentId.isEmpty() || overrideConfiguration)
    {
        return false;
    }

    const QString removedConnectionId = currentId;
    auto next = readableSettings(connectionBackend->connectionPath(""));
    if (!next || !syncCurrent()) return false;
    if (!connectionBackend->setActiveConnection(""))
    {
        return false;
    }

    if (!connectionBackend->removeConnection(removedConnectionId))
    {
        connectionBackend->setActiveConnection(removedConnectionId);
        return false;
    }

    currentSettings = std::move(next);
    currentId.clear();
    return true;
}

QString SavedConnectionService::normalizeConnectionId(const QString &name) const
{
    return connectionBackend->normalizeConnectionId(name);
}

bool SavedConnectionService::silentStartEnabled() const
{
    return connectionBackend->silentStartEnabled();
}

bool SavedConnectionService::migrateAutoStartSetting(bool enabled)
{
    return connectionBackend->setAutoStartEnabled(enabled);
}

bool SavedConnectionService::syncCurrent()
{
    if (QFileInfo::exists(currentSettings->fileName()) && !SettingsMigrator::readableFile(currentSettings->fileName())) return false;
    currentSettings->sync();
    return currentSettings->status() == QSettings::NoError;
}

bool SavedConnectionService::validPublicChanges(const QVariantMap &changes)
{
    for (auto it=changes.cbegin();it!=changes.cend();++it)
        if (!DefaultSettings::isPublicKey(it.key()) || it.key()=="Common/ConfigVersion") return false;
    return true;
}
bool SavedConnectionService::writePublic(QSettings &settings,const QVariantMap &changes)
{
    if (settings.status()!=QSettings::NoError || !validPublicChanges(changes)) return false;
    if (QFileInfo::exists(settings.fileName()) && !SettingsMigrator::readableFile(settings.fileName())) return false;
    if (changes.isEmpty()) return true;
    QVariantMap previous;
    for (auto it=changes.cbegin();it!=changes.cend();++it) previous.insert(it.key(),settings.value(it.key()));
    for (auto it=changes.cbegin();it!=changes.cend();++it) settings.setValue(it.key(),it.value());
    if (SettingsMigrator::finish(settings)) return true;
    for (auto it=previous.cbegin();it!=previous.cend();++it) {
        if (it.value().isValid()) settings.setValue(it.key(),it.value());
        else settings.remove(it.key());
    }
    settings.sync();
    return false;
}
