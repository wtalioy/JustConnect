#include "profilemanager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QTemporaryDir>
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

ProfileManager::ProfileManager(const QString &storageRoot)
{
    configRootPath = storageRoot.isEmpty()
        ? QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        : storageRoot;
    profilesPath = QDir(configRootPath).filePath("profiles");
    statePath = QDir(configRootPath).filePath("state.ini");
    defaultProfilePath = QDir(configRootPath).filePath("config.ini");

    ensureStorage();
}

QStringList ProfileManager::listProfiles() const
{
    QDir profilesDir(profilesPath);
    QStringList profiles;
    for (const QFileInfo &entry : profilesDir.entryInfoList(QStringList() << "*.ini", QDir::Files, QDir::Name))
    {
        profiles << entry.baseName();
    }
    return profiles;
}

QString ProfileManager::activeProfile() const
{
    QSettings state(statePath, QSettings::IniFormat);
    QString profileId = normalizeProfileId(state.value("Profile/Active").toString());

    if (!QFileInfo::exists(profilePath(profileId)))
    {
        profileId = "";
        if (!QFileInfo::exists(profilePath(profileId)))
        {
            createEmptyFile(profilePath(profileId));
        }
        writeState(statePath,"Profile/Active",profileId);
    }
    return profileId;
}

bool ProfileManager::setActiveProfile(const QString &profileId) const
{
    const QString normalizedId = normalizeProfileId(profileId);
    if (!QFileInfo(profilePath(normalizedId)).isFile())
    {
        return false;
    }

    return writeState(statePath,"Profile/Active",normalizedId);
}

QString ProfileManager::profilePath(const QString &profileId) const
{
    QString normalizedId = normalizeProfileId(profileId);
    if (normalizedId.isEmpty())
    {
        return defaultProfilePath;
    }
    return QDir(profilesPath).filePath(normalizedId + ".ini");
}

QString ProfileManager::createProfile(const QString &requestedName, const QString &sourcePath) const
{
    const QString normalizedId = ensureUniqueProfileId(normalizeProfileId(requestedName));
    const QString path = profilePath(normalizedId);

    if (!sourcePath.isEmpty())
    {
        if (!QFileInfo(sourcePath).isFile()) return {};
        QTemporaryDir folder;
        if (!folder.isValid()) return {};
        QSettings source(sourcePath,QSettings::IniFormat);
        QSettings draft(folder.filePath("public.ini"),QSettings::IniFormat);
        if (!SettingsMigrator::publicDraft(source,draft) || !QFile::copy(draft.fileName(),path)) return {};
    }
    else
    {
        if (!createEmptyFile(path))
        {
            return {};
        }
    }

    return normalizedId;
}

bool ProfileManager::renameProfile(const QString &oldId, const QString &newId) const
{
    const QString sourceId = normalizeProfileId(oldId);
    const QString targetId = normalizeProfileId(newId);
    if (sourceId.isEmpty() || targetId.isEmpty() || sourceId == targetId)
    {
        return false;
    }

    const QString sourcePath = profilePath(sourceId);
    const QString targetPath = profilePath(targetId);
    if (!QFileInfo::exists(sourcePath) || QFileInfo::exists(targetPath))
    {
        return false;
    }

    return QFile::rename(sourcePath, targetPath);
}

bool ProfileManager::removeProfile(const QString &profileId) const
{
    const QString normalizedId = normalizeProfileId(profileId);
    if (normalizedId.isEmpty())
    {
        return false;
    }
    return QFile::remove(profilePath(normalizedId));
}

QString ProfileManager::normalizeProfileId(const QString &name) const
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

bool ProfileManager::autoStartEnabled() const
{
    QSettings state(statePath, QSettings::IniFormat);
    return state.value("Global/AutoStart", false).toBool();
}

bool ProfileManager::setAutoStartEnabled(bool enabled) const
{
    return writeState(statePath,"Global/AutoStart",enabled);
}

bool ProfileManager::silentStartEnabled() const
{
    QSettings state(statePath, QSettings::IniFormat);
    return state.value("Global/SilentStart", false).toBool();
}

bool ProfileManager::setSilentStartEnabled(bool enabled) const
{
    return writeState(statePath,"Global/SilentStart",enabled);
}

QString ProfileManager::controllerAddress() const
{
    QSettings state(statePath,QSettings::IniFormat);
    return state.value("Global/ControllerAddress").toString();
}

bool ProfileManager::setControllerAddress(const QString &address) const
{
    return writeState(statePath,"Global/ControllerAddress",address);
}

bool ProfileManager::closeToTray() const
{
    QSettings state(statePath,QSettings::IniFormat);
    const auto value=state.value("Global/CloseToTray",true).toString().toLower();
    return value!="false" && value!="0";
}

bool ProfileManager::setCloseToTray(bool enabled) const
{
    return writeState(statePath,"Global/CloseToTray",enabled);
}

QString ProfileManager::ensureUniqueProfileId(const QString &baseId) const
{
    QString candidate = baseId;
    if (candidate.isEmpty())
    {
        candidate = "profile";
    }

    if (!QFileInfo::exists(profilePath(candidate)))
    {
        return candidate;
    }

    int suffix = 2;
    while (QFileInfo::exists(profilePath(candidate + "_" + QString::number(suffix))))
    {
        suffix++;
    }
    return candidate + "_" + QString::number(suffix);
}

void ProfileManager::ensureStorage() const
{
    QDir configRoot(configRootPath);
    if (!configRoot.exists())
    {
        configRoot.mkpath(".");
    }

    QDir profilesDir(profilesPath);
    if (!profilesDir.exists())
    {
        profilesDir.mkpath(".");
    }
}

QString ProfileManager::language() const
{
    return QSettings(statePath,QSettings::IniFormat).value("Global/Language","en").toString();
}
bool ProfileManager::setApplicationPreferences(const QString &language,bool closeToTray) const
{
    if (!supportsLanguage(language)) return false;
    return writeState(statePath,{{"Global/Language",language},{"Global/CloseToTray",closeToTray}});
}

bool ProfileManager::supportsLanguage(const QString &language)
{
    return language=="en" || language=="zh_CN";
}
