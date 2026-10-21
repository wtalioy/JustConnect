#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include "application/applicationconstants.h"
#include <QSettings>
#include <QTemporaryDir>

#include "application/settingsmigrator.h"
#include "application/defaultsettings.h"

namespace
{
bool validatesReadOnlySourcesWithoutChangingThem()
{
    QTemporaryDir folder;const auto path=folder.filePath("readonly.ini");
    const QByteArray bytes="[Credential]\nUsername=alice\nPassword=legacy-value\n[OtherAccount]\nTicket=retained\n";
    {QFile file(path);if (!file.open(QIODevice::WriteOnly) || file.write(bytes)!=bytes.size()) return false;}
    if (!QFile::setPermissions(path,QFile::ReadOwner)) return false;
    const auto temporaryDirectories=[] {
        return QDir(QDir::tempPath()).entryList({QCoreApplication::applicationName()+"-*"},QDir::Dirs|QDir::NoDotAndDotDot,QDir::Name);
    };
    const auto before=temporaryDirectories();
    const bool valid=SettingsMigrator::readableFile(path) && SettingsMigrator::readableFile(path)
        && !QFileInfo(path).permission(QFile::WriteOwner) && temporaryDirectories()==before;
    QFile source(path);const bool retained=source.open(QIODevice::ReadOnly) && source.readAll()==bytes;source.close();
    return QFile::setPermissions(path,QFile::ReadOwner|QFile::WriteOwner) && valid && retained;
}

bool exportsOnlyPublicConfiguration()
{
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    QSettings source(folder.filePath("source.ini"),QSettings::IniFormat);
    DefaultSettings::reset(source);
    source.setValue("Credential/Username","alice");
    source.setValue("Credential/Password","encoded-secret");
    source.setValue("Credential/TOTPSecret","totp-secret");
    source.setValue("Credential/OtherAccount/Ticket","ticket-secret");
    source.setValue("JustConnect/LoginURL","https://id.example.invalid/?state=session-secret");
    source.setValue("JustConnect/ServerAddress","vpn.example.invalid");
    source.setValue("JustConnect/ServerPort",8443);
    source.setValue("JustConnect/AuthID","selected-method");
    source.setValue("JustConnect/SOCKS5Port",0);
    source.setValue("Unknown/Cookie","unknown-secret");
    source.sync();
    QFile file(source.fileName());
    if (!file.open(QIODevice::ReadOnly)) return false;
    const auto before=file.readAll();file.close();
    const auto target=folder.filePath("export.ini");
    if (!DefaultSettings::exportTo(source,target)) return false;
    QSettings exported(target,QSettings::IniFormat);
    for (const auto &key:QStringList{"Credential/Password","Credential/TOTPSecret","Credential/OtherAccount/Ticket","JustConnect/LoginURL","Unknown/Cookie"})
        if (exported.contains(key)) return false;
    if (exported.value("JustConnect/ServerAddress")!="vpn.example.invalid"
        || exported.value("JustConnect/ServerPort")!=8443 || exported.value("JustConnect/AuthID")!="selected-method"
        || exported.value("Credential/Username")!="alice" || exported.value("JustConnect/SOCKS5Port")!=0
        || SettingsMigrator::prepare(exported)==SettingsMigrationAction::Failed || !SettingsMigrator::finish(exported)) return false;
    if (DefaultSettings::exportTo(source,source.fileName())) return false;
#ifdef Q_OS_UNIX
    const auto alias=folder.filePath("source-link.ini");
    if (!QFile::link(source.fileName(),alias) || DefaultSettings::exportTo(source,alias)) return false;
#endif
    if (DefaultSettings::exportTo(source,folder.path()) || !file.open(QIODevice::ReadOnly)) return false;
    return file.readAll()==before;
}

bool preparesPublicDraftWithoutCopyingSecrets()
{
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    for (const int version:{4,8,42}) {
        QSettings source(folder.filePath(QString::number(version)+"-source.ini"),QSettings::IniFormat);
        source.setValue("Common/ConfigVersion",version);
        source.setValue("Credential/Username","alice");source.setValue("Credential/Password","private password");
        source.setValue("Credential/TOTPSecret","private TOTP");source.setValue("Credential/StoreID","private namespace");
        source.setValue("JustConnect/LoginURL","https://id.example.invalid/?state=private-session");
        source.setValue("OtherAccount/Ticket","private ticket");source.setValue("Unknown/Cookie","private cookie");
        source.setValue("ZJUConnect/ServerAddress","legacy.example.invalid");source.setValue("ZJUConnect/ServerPort",8443);
        source.setValue("ZJUConnect/DisableZJUDNS",true);source.setValue("ZJUConnect/Secret","legacy private value");
        source.setValue("JustConnect/ServerAddress","current.example.invalid");
        if (version!=4) source.setValue("JustConnect/Protocol","atrust");
        source.sync();QFile file(source.fileName());if (!file.open(QIODevice::ReadOnly)) return false;
        const auto original=file.readAll();file.close();
        QSettings draft(folder.filePath(QString::number(version)+"-draft.ini"),QSettings::IniFormat);
        if (!SettingsMigrator::publicDraft(source,draft) || draft.value("Credential/Username")!="alice"
            || draft.value("JustConnect/ServerAddress")!="current.example.invalid" || draft.value("JustConnect/ServerPort")!=8443
            || !draft.value("JustConnect/DisableRemoteDNS").toBool() || draft.value("Common/NeedsConfiguration").toBool()!=(version==4)
            || draft.value("Common/ConfigVersion").toInt()!=(version==42 ? 42 : ApplicationConstants::ConfigVersion)) return false;
        for (const auto &key:QStringList{"Credential/Password","Credential/TOTPSecret","Credential/StoreID","JustConnect/LoginURL","OtherAccount/Ticket","Unknown/Cookie","ZJUConnect/Secret","JustConnect/Protocol"})
            if (draft.contains(key)) return false;
        for (const auto &key:draft.allKeys()) if (key.startsWith("ZJUConnect/")) return false;
        if (!file.open(QIODevice::ReadOnly) || file.readAll()!=original) return false;
        draft.setValue("Unknown/Unrelated","preserved");draft.sync();
        if (SettingsMigrator::publicDraft(source,draft) || draft.value("Unknown/Unrelated")!="preserved") return false;
    }
    return true;
}

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
        settings.setValue("JustConnect/LoginURL","https://id.example.invalid/?session=obsolete");
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
            || saved.contains("JustConnect/LoginURL") || saved.contains("JustConnect/TUNMode") || saved.contains("Credential/CertPassword") || saved.contains("JustConnect/Protocol"))) return false;
        if (version==42 && saved.value("JustConnect/LoginURL")!="https://id.example.invalid/?session=obsolete") return false;
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
    return validatesReadOnlySourcesWithoutChangingThem()
        && preparesPublicDraftWithoutCopyingSecrets()
        && exportsOnlyPublicConfiguration()
        && renamesPreviewSettingsWithoutLosingValues()
        && preservesAlreadyRenamedSettings()
        && requiresConfirmationForOldProtocols()
        && upgradesWithoutResettingValidProfiles()
        && failedSaveRemainsRetryable() ? 0 : 1;
}
