#include "profileservice.h"

#include <QFileInfo>
#include <QSettings>

#include <utility>

#include "application/profilebackend.h"
#include "application/defaultsettings.h"
#include "application/settingsmigrator.h"

namespace {
std::unique_ptr<QSettings> readableProfile(const QString &path)
{
    if (!SettingsMigrator::readableFile(path)) return {};
    auto settings = std::make_unique<QSettings>(path, QSettings::IniFormat);
    settings->sync();
    if (settings->status() != QSettings::NoError) return {};
    return settings;
}
}

ProfileService::ProfileService(
    std::unique_ptr<ProfileBackend> backend,
    const QString &overrideConfigPath,
    QObject *parent
)
    : QObject(parent),
      profileBackend(std::move(backend)),
      overrideConfiguration(!overrideConfigPath.isEmpty())
{
    if (!overrideConfiguration)
    {
        currentId = profileBackend->activeProfile();
        currentSettings = std::make_unique<QSettings>(
            profileBackend->profilePath(currentId),
            QSettings::IniFormat
        );
    }
    else
    {
        currentId = "custom";
        currentSettings = std::make_unique<QSettings>(overrideConfigPath, QSettings::IniFormat);
    }
}

ProfileService::~ProfileService()
{
    currentSettings->sync();
}

QSettings *ProfileService::settings() const
{
    return currentSettings.get();
}

QString ProfileService::currentProfileId() const
{
    return currentId;
}

QStringList ProfileService::profiles() const
{
    return profileBackend->listProfiles();
}

bool ProfileService::usesOverrideConfiguration() const
{
    return overrideConfiguration;
}

bool ProfileService::switchTo(const QString &profileId)
{
    if (!overrideConfiguration && profileId == currentId)
    {
        return true;
    }

    auto next = readableProfile(profileBackend->profilePath(profileId));
    if (!next || !syncCurrent()) return false;
    if (!profileBackend->setActiveProfile(profileId))
    {
        return false;
    }

    currentSettings = std::move(next);
    currentId = profileId;
    overrideConfiguration = false;
    return true;
}

QString ProfileService::createAndSwitch(const QString &requestedName)
{
    if (!syncCurrent()) return {};
    const QString profileId = profileBackend->createProfile(
        requestedName,
        currentSettings->fileName()
    );
    if (profileId.isEmpty() || !switchTo(profileId))
    {
        if (!profileId.isEmpty())
        {
            profileBackend->removeProfile(profileId);
        }
        return {};
    }
    return profileId;
}

bool ProfileService::renameCurrent(const QString &newProfileId)
{
    if (currentId.isEmpty() || overrideConfiguration)
    {
        return false;
    }

    if (!syncCurrent()) return false;
    if (!profileBackend->renameProfile(currentId, newProfileId))
    {
        return false;
    }

    const QString previousId = currentId;
    if (!profileBackend->setActiveProfile(newProfileId))
    {
        profileBackend->renameProfile(newProfileId, previousId);
        return false;
    }

    currentId = newProfileId;
    currentSettings = std::make_unique<QSettings>(
        profileBackend->profilePath(currentId),
        QSettings::IniFormat
    );
    return true;
}

bool ProfileService::removeCurrentAndSwitchToDefault()
{
    if (currentId.isEmpty() || overrideConfiguration)
    {
        return false;
    }

    const QString removedProfileId = currentId;
    auto next = readableProfile(profileBackend->profilePath(""));
    if (!next || !syncCurrent()) return false;
    if (!profileBackend->setActiveProfile(""))
    {
        return false;
    }

    if (!profileBackend->removeProfile(removedProfileId))
    {
        profileBackend->setActiveProfile(removedProfileId);
        return false;
    }

    currentSettings = std::move(next);
    currentId.clear();
    return true;
}

QString ProfileService::normalizeProfileId(const QString &name) const
{
    return profileBackend->normalizeProfileId(name);
}

bool ProfileService::silentStartEnabled() const
{
    return profileBackend->silentStartEnabled();
}

bool ProfileService::migrateAutoStartSetting(bool enabled)
{
    return profileBackend->setAutoStartEnabled(enabled);
}

bool ProfileService::syncCurrent()
{
    if (QFileInfo::exists(currentSettings->fileName()) && !SettingsMigrator::readableFile(currentSettings->fileName())) return false;
    currentSettings->sync();
    return currentSettings->status() == QSettings::NoError;
}

bool ProfileService::validPublicChanges(const QVariantMap &changes)
{
    for (auto it=changes.cbegin();it!=changes.cend();++it)
        if (!DefaultSettings::isPublicKey(it.key()) || it.key()=="Common/ConfigVersion") return false;
    return true;
}
bool ProfileService::writePublic(QSettings &settings,const QVariantMap &changes)
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
