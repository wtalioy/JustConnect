#include <QCoreApplication>
#include <QDebug>
#include <QSettings>
#include <QTemporaryDir>

#include "application/settingsmigrator.h"
#include "application/defaultsettings.h"

namespace
{
bool renamesPreviewSettingsWithoutLosingValues()
{
    QTemporaryDir directory;
    const QString path = directory.filePath("profile.ini");
    {
        QSettings settings(path, QSettings::IniFormat);
        settings.setValue("Common/ConfigVersion", 8);
        settings.setValue("ZJUConnect/ServerAddress", "vpn.example.edu");
        settings.setValue("ZJUConnect/ServerPort", 8443);
        settings.setValue("ZJUConnect/DisableZJUDNS", true);
        settings.setValue("ZJUConnect/ZJUDefault", true);
        settings.setValue("Credential/Username", "alice");
        if (SettingsMigrator::prepare(settings) != SettingsMigrationAction::None)
        {
            return false;
        }
        SettingsMigrator::prepare(settings);
    }
    QSettings saved(path, QSettings::IniFormat);
    return saved.value("JustConnect/ServerAddress").toString() == "vpn.example.edu"
        && saved.value("JustConnect/ServerPort").toInt() == 8443
        && saved.value("JustConnect/DisableRemoteDNS").toBool()
        && saved.value("Credential/Username").toString() == "alice"
        && !saved.childGroups().contains("ZJUConnect")
        && !saved.contains("JustConnect/ZJUDefault");
}

bool preservesAlreadyRenamedSettings()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    settings.setValue("Common/ConfigVersion", 8);
    settings.setValue("ZJUConnect/ServerAddress", "old.example.edu");
    settings.setValue("JustConnect/ServerAddress", "new.example.edu");
    SettingsMigrator::prepare(settings);
    return settings.value("JustConnect/ServerAddress").toString() == "new.example.edu";
}

bool startsWithoutSchoolSpecificDefaults()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    DefaultSettings::reset(settings);
    return settings.value("JustConnect/ServerAddress").toString().isEmpty()
        && settings.value("JustConnect/LoginDomain").toString().isEmpty()
        && settings.value("JustConnect/Protocol").toString() == "atrust"
        && !settings.childGroups().contains("ZJUConnect");
}

bool migratesKnownVersions()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    settings.setValue("Common/ConfigVersion", 4);

    const auto action = SettingsMigrator::prepare(settings);
    const bool passed =
        action == SettingsMigrationAction::None
        && settings.value("JustConnect/Protocol").toString() == "easyconnect";
    if (!passed)
    {
        qCritical() << "migratesKnownVersions failed";
    }
    return passed;
}

bool recommendsResetForUnsupportedVersions()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    settings.setValue("Common/ConfigVersion", 5);
    const bool passed =
        SettingsMigrator::prepare(settings) ==
        SettingsMigrationAction::RecommendReset;
    if (!passed)
    {
        qCritical() << "recommendsResetForUnsupportedVersions failed";
    }
    return passed;
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return renamesPreviewSettingsWithoutLosingValues()
        && preservesAlreadyRenamedSettings()
        && startsWithoutSchoolSpecificDefaults()
        && migratesKnownVersions()
        && recommendsResetForUnsupportedVersions() ? 0 : 1;
}
