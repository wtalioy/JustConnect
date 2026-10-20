#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include "application/applicationconstants.h"
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

bool requiresConfirmationForOldProtocols()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("legacy.ini"),QSettings::IniFormat);
    settings.setValue("Common/ConfigVersion",4);
    settings.setValue("JustConnect/ServerAddress","retained-legacy.example.edu");
    settings.setValue("Credential/CertFile","retained-on-disk.p12");
    settings.setValue("JustConnect/ExtraArguments","obsolete argument");
    return SettingsMigrator::prepare(settings)==SettingsMigrationAction::None
        && settings.value("Common/NeedsConfiguration").toBool()
        && SettingsMigrator::finish(settings)
        && settings.value("JustConnect/ServerAddress")=="retained-legacy.example.edu"
        && !settings.contains("JustConnect/Protocol") && !settings.contains("Credential/CertFile")
        && !settings.contains("JustConnect/ExtraArguments");
}

bool upgradesWithoutResettingValidProfiles()
{
    QTemporaryDir directory;
    const QString otherPath = directory.filePath("other.ini");
    QFile other(otherPath);
    if (!other.open(QIODevice::WriteOnly) || other.write("other application data") < 0) return false;
    other.close();
    for (const int version : {-1, 4, 5, 6, 7, 8, 9, 42})
    {
        const QString path = directory.filePath(QString::number(version) + ".ini");
        QSettings settings(path, QSettings::IniFormat);
        if (version != -1) settings.setValue("Common/ConfigVersion", version);
        settings.setValue("JustConnect/Protocol", "atrust");
        settings.setValue("JustConnect/ServerAddress", "vpn.example.edu");
        settings.setValue("JustConnect/ServerPort", 8443);
        settings.setValue("JustConnect/AuthType", "httpsOauth2");
        settings.setValue("JustConnect/LoginDomain", "retained-domain");
        settings.setValue("JustConnect/SOCKS5Port", 0);
        settings.setValue("Credential/Password", "retained encoded password");
        settings.setValue("Credential/AccountB/Ticket", "retained account ticket");
        settings.setValue("Credential/CertPassword", "obsolete certificate password");
        settings.setValue("JustConnect/ExtraArguments", "obsolete arguments");
        settings.setValue("JustConnect/TUNMode", true);
        settings.setValue("OtherApplication/Value", "retained external setting");
        const auto action = SettingsMigrator::prepare(settings);
        if (action != (version == 6 ? SettingsMigrationAction::MigrateAutoStart : SettingsMigrationAction::None)
            || !SettingsMigrator::finish(settings)) return false;
        QSettings saved(path, QSettings::IniFormat);
        if (version <= ApplicationConstants::ConfigVersion && (saved.contains("JustConnect/ExtraArguments")
            || saved.contains("JustConnect/TUNMode") || saved.contains("Credential/CertPassword") || saved.contains("JustConnect/Protocol"))) return false;
        if (saved.value("JustConnect/ServerAddress") != "vpn.example.edu"
            || saved.value("JustConnect/ServerPort") != 8443
            || saved.value("JustConnect/AuthType") != "httpsOauth2"
            || saved.value("JustConnect/LoginDomain") != "retained-domain"
            || saved.value("JustConnect/SOCKS5Port") != 0
            || saved.value("JustConnect/HTTPPort") != 11081
            || saved.value("Credential/Password") != "retained encoded password"
            || saved.value("Credential/AccountB/Ticket") != "retained account ticket"
            || saved.value("OtherApplication/Value") != "retained external setting"
            || saved.value("Common/ConfigVersion").toInt() != (version == 42 ? 42 : ApplicationConstants::ConfigVersion)) return false;
    }
    if (!other.open(QIODevice::ReadOnly)) return false;
    return other.readAll() == "other application data";
}

bool failedSaveRemainsRetryable()
{
    QTemporaryDir directory;
    const auto blocked = directory.filePath("blocked.ini");
    if (!QDir().mkdir(blocked)) return false;
    QSettings settings(blocked, QSettings::IniFormat);
    settings.setValue("Common/ConfigVersion", 6);
    settings.setValue("ZJUConnect/ServerAddress", "retained.example.edu");
    settings.setValue("Common/AutoStart",true);
    settings.setValue("JustConnect/ExtraArguments","retained until save succeeds");
    if (SettingsMigrator::prepare(settings) != SettingsMigrationAction::Failed
        || !settings.contains("ZJUConnect/ServerAddress")) return false;
    if (SettingsMigrator::finish(settings)) return false;
    return settings.value("Common/ConfigVersion").toInt() == 6
        && settings.value("Common/AutoStart").toBool()
        && settings.value("JustConnect/ExtraArguments")=="retained until save succeeds";
}

}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return renamesPreviewSettingsWithoutLosingValues()
        && preservesAlreadyRenamedSettings()
        && requiresConfirmationForOldProtocols()
        && upgradesWithoutResettingValidProfiles()
        && failedSaveRemainsRetryable() ? 0 : 1;
}
