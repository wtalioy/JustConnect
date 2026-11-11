#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QSettings>

#include "infrastructure/settings/savedconnectionstore.h"

namespace
{
QByteArray read(const QString &path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}
bool createsIndependentEmptyConnections()
{
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    SavedConnectionStore manager(folder.path());
    QSettings source(manager.connectionPath(""), QSettings::IniFormat);
    source.setValue("JustConnect/ServerAddress", "vpn.example.invalid");
    source.setValue("Credential/Username", "alice");
    source.sync();
    const auto original = read(source.fileName());
    if (original.isEmpty() || manager.createConnection("work") != "work"
        || manager.createConnection("work") != "work_2") return false;
    return read(source.fileName()) == original
        && QFileInfo(manager.connectionPath("work")).size() == 0
        && QFileInfo(manager.connectionPath("work_2")).size() == 0;
}

bool publishesDraftWithItsCredentialScope()
{
    QTemporaryDir directory,staging;
    SavedConnectionStore manager(directory.path());
    QSettings draft(staging.filePath("draft.ini"),QSettings::IniFormat);
    draft.setValue("JustConnect/ServerAddress","vpn.new-campus.invalid");
    draft.setValue("Credential/StoreID","eb721658-b0cc-48d4-ace0-a4e469e992b8");
    draft.sync();
    const auto expected=read(draft.fileName());
    if (expected.isEmpty() || !manager.createConnection("missing",staging.filePath("missing.ini")).isEmpty()
        || !manager.listConnections().isEmpty() || manager.createConnection("campus")!="campus"
        || manager.createConnection("campus",draft.fileName())!="campus_2") return false;
    return QFileInfo(manager.connectionPath("campus")).size()==0
        && read(manager.connectionPath("campus_2"))==expected && read(draft.fileName())==expected;
}

bool rejectsMalformedStateAndRecovers()
{
    QTemporaryDir directory;
    SavedConnectionStore manager(directory.path());
    const auto target=manager.createConnection("target");
    const auto path=directory.filePath("state.ini");
    const QByteArray malformed="[unclosed group\nGlobal/SilentStart=false\n";
    {QFile file(path);if (!file.open(QIODevice::WriteOnly) || file.write(malformed)!=malformed.size()) return false;}
    const bool selected=manager.setActiveConnection(target),autoStart=manager.setAutoStartEnabled(true),silentStart=manager.setSilentStartEnabled(true);
    if (target.isEmpty() || selected || autoStart || silentStart || read(path)!=malformed) {
        qCritical()<<"malformed state must not be rewritten by selection or preference saves"<<selected<<autoStart<<silentStart<<read(path);return false;
    }
    const QByteArray repaired="[Global]\nSilentStart=false\nAutoStart=false\n[Connection]\nActive=\n";
    {QFile file(path);if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(repaired)!=repaired.size()) return false;}
    if (!manager.setSilentStartEnabled(true) || !manager.setAutoStartEnabled(true) || !manager.setActiveConnection(target)) return false;
    SavedConnectionStore reopened(directory.path());
    return reopened.silentStartEnabled() && reopened.autoStartEnabled() && reopened.activeConnectionId()==target;
}

bool closeBehaviorIsGlobalAndFailedWritesRetainThePreference()
{
    QTemporaryDir directory;SavedConnectionStore manager(directory.path());
    if (!manager.closeToTray()) return false;
    {QSettings state(directory.filePath("state.ini"),QSettings::IniFormat);state.setValue("Global/CloseToTray",QString());state.sync();}
    if (!manager.closeToTray() || !manager.setCloseToTray(false)) return false;
    const auto profile=manager.createConnection("preset");
    if (profile.isEmpty() || !manager.setActiveConnection(profile) || SavedConnectionStore(directory.path()).closeToTray()) return false;
    QSettings preset(manager.connectionPath(profile),QSettings::IniFormat);
    if (preset.contains("Global/CloseToTray") || preset.contains("Common/CloseToTray")) return false;
    const auto state=directory.filePath("state.ini");
    const QByteArray malformed="[unclosed group\nGlobal/CloseToTray=false\n";
    {QFile file(state);if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(malformed)!=malformed.size()) return false;}
    if (manager.setCloseToTray(true) || read(state)!=malformed) return false;
    const QByteArray repaired="[Global]\nCloseToTray=false\n";
    {QFile file(state);if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(repaired)!=repaired.size()) return false;}
    return !SavedConnectionStore(directory.path()).closeToTray() && manager.setCloseToTray(true) && SavedConnectionStore(directory.path()).closeToTray();
}

bool languageAndClosePreferencesAreGlobalAndSavedTogether()
{
    QTemporaryDir directory;SavedConnectionStore manager(directory.path());
    if (manager.language()!="en" || !manager.setApplicationPreferences("zh_CN",false)) return false;
    const auto profile=manager.createConnection("other");
    if (profile.isEmpty() || !manager.setActiveConnection(profile) || SavedConnectionStore(directory.path()).language()!="zh_CN" || manager.closeToTray()) return false;
    const auto before=read(directory.filePath("state.ini"));
    if (manager.setApplicationPreferences("unsupported",true) || read(directory.filePath("state.ini"))!=before) return false;
    const auto state=directory.filePath("state.ini");const QByteArray broken="[broken";
    {QFile file(state);if (!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(broken)!=broken.size())return false;}
    return !manager.setApplicationPreferences("en",true) && read(state)==broken;
}

bool controllerChoiceIsGlobalAndFailedWritesPreserveIt()
{
    QTemporaryDir directory;SavedConnectionStore manager(directory.path());
    const QString address="http://127.0.0.1:12345";
    if (!manager.controllerAddress().isEmpty() || !manager.setControllerAddress(address)) return false;
    const auto profile=manager.createConnection("campus");
    if (profile.isEmpty() || !manager.setActiveConnection(profile) || SavedConnectionStore(directory.path()).controllerAddress()!=address) return false;
    QSettings campus(manager.connectionPath(profile),QSettings::IniFormat);
    if (campus.contains("Global/ControllerAddress")) return false;
    const auto state=directory.filePath("state.ini");
    const QByteArray malformed="[unclosed group\nGlobal/ControllerAddress=unchanged\n";
    {QFile file(state);if(!file.open(QIODevice::WriteOnly|QIODevice::Truncate) || file.write(malformed)!=malformed.size())return false;}
    return !manager.setControllerAddress(QString()) && read(state)==malformed;
}

bool createsPhysicalFilesForEmptyProfiles()
{
    QTemporaryDir directory;
    SavedConnectionStore manager(directory.path());

    if (!manager.activeConnectionId().isEmpty()
        || !QFileInfo::exists(manager.connectionPath(""))
        || !manager.setActiveConnection(""))
    {
        qCritical() << "default profile file was not created";
        return false;
    }

    const QString connectionId = manager.createConnection("empty");
    if (connectionId != "empty"
        || !QFileInfo::exists(manager.connectionPath(connectionId))
        || !manager.listConnections().contains(connectionId)
        || !manager.setActiveConnection(connectionId))
    {
        qCritical() << "empty named profile file was not created";
        return false;
    }
    const auto stateProfile = manager.createConnection("state");
    if (stateProfile != "state" || !manager.listConnections().contains(stateProfile)
        || !manager.setActiveConnection(stateProfile)
        || SavedConnectionStore(directory.path()).activeConnectionId() != stateProfile)
    {
        qCritical() << "named state profile was confused with the global state file";
        return false;
    }
    if (!manager.setAutoStartEnabled(true) || !SavedConnectionStore(directory.path()).autoStartEnabled()
        || !manager.setSilentStartEnabled(true) || !SavedConnectionStore(directory.path()).silentStartEnabled()) return false;
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
    return languageAndClosePreferencesAreGlobalAndSavedTogether() && controllerChoiceIsGlobalAndFailedWritesPreserveIt() && closeBehaviorIsGlobalAndFailedWritesRetainThePreference() && createsIndependentEmptyConnections() && publishesDraftWithItsCredentialScope() && createsPhysicalFilesForEmptyProfiles() && rejectsMalformedStateAndRecovers() ? 0 : 1;
}
