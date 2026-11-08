#include "savedconnectionstore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include "application/settingsmigrator.h"

namespace
{
bool writeState(const QString &path,const QVariantMap &values)
{
    if (QFileInfo::exists(path) && !SettingsMigrator::readableFile(path)) return false;
    QSettings state(path,QSettings::IniFormat);
    state.sync();
    if (state.status()!=QSettings::NoError) return false;
    QVariantMap previous;
    for (auto it=values.begin();it!=values.end();++it) {
        previous.insert(it.key(),state.value(it.key()));
        state.setValue(it.key(),it.value());
    }
    state.sync();
    bool saved=state.status()==QSettings::NoError;
    for (auto it=values.begin();it!=values.end();++it) saved=saved && state.value(it.key())==it.value();
    if (saved) return true;
    for (auto it=previous.begin();it!=previous.end();++it) {
        if (it.value().isValid()) state.setValue(it.key(),it.value());
        else state.remove(it.key());
    }
    state.sync();
    return false;
}
bool writeState(const QString &path,const QString &key,const QVariant &value)
{
    return writeState(path,{{key,value}});
}

bool createEmptyFile(const QString &path)
{
    const QFileInfo fileInfo(path);
    if (fileInfo.exists())
    {
        return fileInfo.isFile();
    }

    QFile file(path);
    return file.open(QIODevice::WriteOnly | QIODevice::NewOnly);
}
}

SavedConnectionStore::SavedConnectionStore(const QString &storageRoot)
{
    configRootPath = storageRoot.isEmpty()
        ? QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        : storageRoot;
    connectionsPath = QDir(configRootPath).filePath("connections");
    statePath = QDir(configRootPath).filePath("state.ini");
    defaultConnectionPath = QDir(configRootPath).filePath("config.ini");

    ensureStorage();
}

QStringList SavedConnectionStore::listConnections() const
{
    QDir connectionsDir(connectionsPath);
    QStringList connectionIds;
    for (const QFileInfo &entry : connectionsDir.entryInfoList(QStringList() << "*.ini", QDir::Files, QDir::Name))
    {
        connectionIds << entry.baseName();
    }
    return connectionIds;
}

QString SavedConnectionStore::activeConnectionId() const
{
    QSettings state(statePath, QSettings::IniFormat);
    QString connectionId = normalizeConnectionId(state.value("Connection/Active").toString());

    if (!QFileInfo::exists(connectionPath(connectionId)))
    {
        connectionId = "";
        if (!QFileInfo::exists(connectionPath(connectionId)))
        {
            createEmptyFile(connectionPath(connectionId));
        }
        writeState(statePath,"Connection/Active",connectionId);
    }
    return connectionId;
}

bool SavedConnectionStore::setActiveConnection(const QString &connectionId) const
{
    const QString normalizedId = normalizeConnectionId(connectionId);
    if (!QFileInfo(connectionPath(normalizedId)).isFile())
    {
        return false;
    }

    return writeState(statePath,"Connection/Active",normalizedId);
}

QString SavedConnectionStore::connectionPath(const QString &connectionId) const
{
    QString normalizedId = normalizeConnectionId(connectionId);
    if (normalizedId.isEmpty())
    {
        return defaultConnectionPath;
    }
    return QDir(connectionsPath).filePath(normalizedId + ".ini");
}

QString SavedConnectionStore::createConnection(const QString &requestedName) const
{
    const QString normalizedId = ensureUniqueConnectionId(normalizeConnectionId(requestedName));
    QFile file(connectionPath(normalizedId));
    return file.open(QIODevice::WriteOnly | QIODevice::NewOnly) ? normalizedId : QString();
}

bool SavedConnectionStore::renameConnection(const QString &oldId, const QString &newId) const
{
    const QString sourceId = normalizeConnectionId(oldId);
    const QString targetId = normalizeConnectionId(newId);
    if (sourceId.isEmpty() || targetId.isEmpty() || sourceId == targetId)
    {
        return false;
    }

    const QString sourcePath = connectionPath(sourceId);
    const QString targetPath = connectionPath(targetId);
    if (!QFileInfo::exists(sourcePath) || QFileInfo::exists(targetPath))
    {
        return false;
    }

    return QFile::rename(sourcePath, targetPath);
}

bool SavedConnectionStore::removeConnection(const QString &connectionId) const
{
    const QString normalizedId = normalizeConnectionId(connectionId);
    if (normalizedId.isEmpty())
    {
        return false;
    }
    return QFile::remove(connectionPath(normalizedId));
}

QString SavedConnectionStore::normalizeConnectionId(const QString &name) const
{
    QString normalized = name.trimmed();
    normalized.replace(QRegularExpression("[^a-zA-Z0-9_-]"), "_");
    normalized.replace(QRegularExpression("_+"), "_");
    if (normalized.startsWith('_'))
    {
        normalized.remove(0, 1);
    }
    if (normalized.endsWith('_'))
    {
        normalized.chop(1);
    }
    return normalized;
}

bool SavedConnectionStore::autoStartEnabled() const
{
    QSettings state(statePath, QSettings::IniFormat);
    return state.value("Global/AutoStart", false).toBool();
}

bool SavedConnectionStore::setAutoStartEnabled(bool enabled) const
{
    return writeState(statePath,"Global/AutoStart",enabled);
}

bool SavedConnectionStore::silentStartEnabled() const
{
    QSettings state(statePath, QSettings::IniFormat);
    return state.value("Global/SilentStart", false).toBool();
}

bool SavedConnectionStore::setSilentStartEnabled(bool enabled) const
{
    return writeState(statePath,"Global/SilentStart",enabled);
}

QString SavedConnectionStore::controllerAddress() const
{
    QSettings state(statePath,QSettings::IniFormat);
    return state.value("Global/ControllerAddress").toString();
}

bool SavedConnectionStore::setControllerAddress(const QString &address) const
{
    return writeState(statePath,"Global/ControllerAddress",address);
}

bool SavedConnectionStore::closeToTray() const
{
    QSettings state(statePath,QSettings::IniFormat);
    const auto value=state.value("Global/CloseToTray",true).toString().toLower();
    return value!="false" && value!="0";
}

bool SavedConnectionStore::setCloseToTray(bool enabled) const
{
    return writeState(statePath,"Global/CloseToTray",enabled);
}

QString SavedConnectionStore::ensureUniqueConnectionId(const QString &baseId) const
{
    QString candidate = baseId;
    if (candidate.isEmpty())
    {
        candidate = "connection";
    }

    if (!QFileInfo::exists(connectionPath(candidate)))
    {
        return candidate;
    }

    int suffix = 2;
    while (QFileInfo::exists(connectionPath(candidate + "_" + QString::number(suffix))))
    {
        suffix++;
    }
    return candidate + "_" + QString::number(suffix);
}

void SavedConnectionStore::ensureStorage() const
{
    QDir configRoot(configRootPath);
    if (!configRoot.exists())
    {
        configRoot.mkpath(".");
    }

    QDir connectionsDir(connectionsPath);
    if (!connectionsDir.exists())
    {
        connectionsDir.mkpath(".");
    }
}

QString SavedConnectionStore::language() const
{
    return QSettings(statePath,QSettings::IniFormat).value("Global/Language","en").toString();
}
bool SavedConnectionStore::setApplicationPreferences(const QString &language,bool closeToTray) const
{
    if (!supportsLanguage(language)) return false;
    return writeState(statePath,{{"Global/Language",language},{"Global/CloseToTray",closeToTray}});
}

bool SavedConnectionStore::supportsLanguage(const QString &language)
{
    return language=="en" || language=="zh_CN";
}
