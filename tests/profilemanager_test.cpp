#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QSettings>

#include "infrastructure/settings/profilemanager.h"

namespace
{
QByteArray read(const QString &path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}
bool copiesOnlyPublicConfiguration()
{
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    ProfileManager manager(folder.path());
    QSettings source(manager.profilePath(""),QSettings::IniFormat);
    source.setValue("Common/ConfigVersion",9);
    source.setValue("Common/SuppressProxyOverrideWarning",true);
    source.setValue("Credential/Username","alice");
    source.setValue("Credential/Password","encoded private password");
    source.setValue("Credential/TOTPSecret","private TOTP");
    source.setValue("Credential/StoreID","11111111-1111-4111-8111-111111111111");
    source.setValue("Credential/OtherAccount/Ticket","private ticket");
    source.setValue("Unknown/Cookie","private cookie");
    source.setValue("JustConnect/LoginURL","https://id.example.invalid/?state=private-session");
    source.setValue("JustConnect/ServerAddress","vpn.example.invalid");source.setValue("JustConnect/ServerPort",8443);
    source.setValue("JustConnect/AuthType","httpsOauth2");source.setValue("JustConnect/AuthID","selected-id");
    source.setValue("JustConnect/AuthSubType","https");source.setValue("JustConnect/LoginDomain","id.example.invalid");
    source.setValue("JustConnect/SOCKS5Port",0);source.setValue("JustConnect/TLSVerify",false);source.sync();
    const auto original=read(source.fileName());
    if (original.isEmpty() || manager.createProfile("copy",source.fileName())!="copy") return false;
    QSettings copy(manager.profilePath("copy"),QSettings::IniFormat);
    if (!copy.value("Common/SuppressProxyOverrideWarning").toBool() || copy.value("Credential/Username")!="alice" || copy.value("JustConnect/ServerAddress")!="vpn.example.invalid"
        || copy.value("JustConnect/ServerPort")!=8443 || copy.value("JustConnect/AuthID")!="selected-id"
        || copy.value("JustConnect/AuthSubType")!="https" || copy.value("JustConnect/LoginDomain")!="id.example.invalid"
        || copy.value("JustConnect/SOCKS5Port")!=0 || copy.value("JustConnect/TLSVerify").toBool()) return false;
    for (const auto &key:QStringList{"Credential/Password","Credential/TOTPSecret","Credential/StoreID","Credential/OtherAccount/Ticket","Unknown/Cookie","JustConnect/LoginURL"})
        if (copy.contains(key)) return false;
    if (read(source.fileName())!=original || manager.createProfile("copy",source.fileName())!="copy_2") return false;
    if (!manager.createProfile("missing",folder.filePath("missing.ini")).isEmpty() || QFileInfo::exists(manager.profilePath("missing"))) return false;
    if (!manager.createProfile("directory",folder.path()).isEmpty() || QFileInfo::exists(manager.profilePath("directory"))) return false;
    const auto invalid=folder.filePath("corrupt.ini");
    const QByteArray malformed="[unclosed group\nprivate=value\n";
    {QFile file(invalid);if (!file.open(QIODevice::WriteOnly) || file.write(malformed)!=malformed.size()) return false;}
    if (!manager.createProfile("corrupt",invalid).isEmpty() || QFileInfo::exists(manager.profilePath("corrupt")) || read(invalid)!=malformed) return false;
    if (!manager.createProfile("corrupt-again",invalid).isEmpty() || read(invalid)!=malformed) return false;
    return read(source.fileName())==original;
}

bool rejectsMalformedStateAndRecovers()
{
    QTemporaryDir directory;
    ProfileManager manager(directory.path());
    const auto target=manager.createProfile("target");
    const auto path=directory.filePath("state.ini");
    const QByteArray malformed="[unclosed group\nGlobal/SilentStart=false\n";
    {QFile file(path);if (!file.open(QIODevice::WriteOnly) || file.write(malformed)!=malformed.size()) return false;}
    const bool selected=manager.setActiveProfile(target),autoStart=manager.setAutoStartEnabled(true),silentStart=manager.setSilentStartEnabled(true);
    if (target.isEmpty() || selected || autoStart || silentStart || read(path)!=malformed) {
        qCritical()<<"malformed state must not be rewritten by selection or preference saves"<<selected<<autoStart<<silentStart<<read(path);return false;
    }
    const QByteArray repaired="[Global]\nSilentStart=false\nAutoStart=false\n[Profile]\nActive=\n";
    {QFile file(path);if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(repaired)!=repaired.size()) return false;}
    if (!manager.setSilentStartEnabled(true) || !manager.setAutoStartEnabled(true) || !manager.setActiveProfile(target)) return false;
    ProfileManager reopened(directory.path());
    return reopened.silentStartEnabled() && reopened.autoStartEnabled() && reopened.activeProfile()==target;
}

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
    if (!manager.setAutoStartEnabled(true) || !ProfileManager(directory.path()).autoStartEnabled()
        || !manager.setSilentStartEnabled(true) || !ProfileManager(directory.path()).silentStartEnabled()) return false;
    // A directory in place of the state file is a real storage failure on every platform.
    if (!QFile::remove(directory.filePath("state.ini")) || !QDir().mkdir(directory.filePath("state.ini"))) return false;
    if (manager.setAutoStartEnabled(false) || manager.setSilentStartEnabled(false)) {
        qCritical() << "autostart preference storage failure was reported as success";
        return false;
    }
    return true;
}
}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    return copiesOnlyPublicConfiguration() && createsPhysicalFilesForEmptyProfiles() && rejectsMalformedStateAndRecovers() ? 0 : 1;
}
