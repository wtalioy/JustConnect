#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include "infrastructure/settings/profilemanager.h"

namespace
{
bool createsPhysicalFilesForEmptyProfiles()
{
    QTemporaryDir directory;
    ProfileManager manager(directory.path());

    if (!manager.activeProfile().isEmpty()
        || !QFileInfo::exists(manager.profilePath(""))
        || !manager.setActiveProfile(""))
    {
        qCritical() << "default profile file was not created";
        return false;
    }

    const QString profileId = manager.createProfile("empty");
    if (profileId != "empty"
        || !QFileInfo::exists(manager.profilePath(profileId))
        || !manager.listProfiles().contains(profileId)
        || !manager.setActiveProfile(profileId))
    {
        qCritical() << "empty named profile file was not created";
        return false;
    }
    if (!manager.setAutoStartEnabled(true) || !ProfileManager(directory.path()).autoStartEnabled()) return false;
    // A directory in place of the state file is a real storage failure on every platform.
    if (!QFile::remove(directory.filePath("state.ini")) || !QDir().mkdir(directory.filePath("state.ini"))) return false;
    if (manager.setAutoStartEnabled(false)) {
        qCritical() << "autostart preference storage failure was reported as success";
        return false;
    }
    return true;
}
}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    return createsPhysicalFilesForEmptyProfiles() ? 0 : 1;
}
