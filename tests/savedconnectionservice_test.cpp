#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QTemporaryDir>

#include <memory>

#include "application/savedconnectionbackend.h"
#include "application/savedconnectionservice.h"

namespace
{
class FakeSavedConnectionBackend : public SavedConnectionBackend
{
public:
    explicit FakeSavedConnectionBackend(const QString &rootPath)
        : rootPath(rootPath)
    {
        QSettings defaultSettings(connectionPath(""), QSettings::IniFormat);
        defaultSettings.sync();
    }

    QStringList listConnections() const override
    {
        QStringList result;
        for (const QFileInfo &file : QDir(rootPath).entryInfoList(
                 {"*.ini"},
                 QDir::Files,
                 QDir::Name
             ))
        {
            if (file.baseName() != "default")
            {
                result << file.baseName();
            }
        }
        return result;
    }

    QString activeConnectionId() const override
    {
        return activeId;
    }

    bool setActiveConnection(const QString &connectionId) const override
    {
        ++activeWrites;
        if (!allowActiveProfileChange)
        {
            return false;
        }
        activeId = connectionId;
        return true;
    }

    QString connectionPath(const QString &connectionId) const override
    {
        return QDir(rootPath).filePath(
            (connectionId.isEmpty() ? QStringLiteral("default") : connectionId) + ".ini"
        );
    }

    QString createConnection(const QString &requestedName,const QString &draftPath) const override
    {
        ++creates;
        const QString id = normalizeConnectionId(requestedName);
        if (!draftPath.isEmpty()) return !id.isEmpty() && QFile::copy(draftPath,connectionPath(id)) ? id : QString();
        QFile file(connectionPath(id));
        return !id.isEmpty() && file.open(QIODevice::WriteOnly | QIODevice::NewOnly) ? id : QString();
    }

    bool renameConnection(
        const QString &oldId,
        const QString &newId
    ) const override
    {
        ++renames;
        return QFile::rename(connectionPath(oldId), connectionPath(newId));
    }

    bool removeConnection(const QString &connectionId) const override
    {
        ++removals;
        return allowProfileRemoval && QFile::remove(connectionPath(connectionId));
    }

    QString normalizeConnectionId(const QString &name) const override
    {
        return name.trimmed();
    }

    bool silentStartEnabled() const override
    {
        return false;
    }

    bool setAutoStartEnabled(bool enabled) const override
    {
        if (!allowAutoStartSave) return false;
        migratedAutoStart = enabled;
        return true;
    }

    mutable QString activeId;
    mutable int activeWrites=0,creates=0,renames=0,removals=0;
    bool allowAutoStartSave = true;
    mutable bool migratedAutoStart = false;
    bool allowActiveProfileChange = true;
    bool allowProfileRemoval = true;

private:
    QString rootPath;
};

bool rejectsUnsavedSourceBeforeChangingProfiles()
{
    QTemporaryDir directory;
    for(const auto &id:QStringList{"work","target","default"}) {
        QSettings seed(directory.filePath(id+".ini"),QSettings::IniFormat);
        seed.setValue("Credential/Username",id);seed.setValue("OtherAccount/Ticket","retained");seed.sync();
    }
    const auto path=directory.filePath("work.ini");
    bool blocked=false;
    {
        auto backend=std::make_unique<FakeSavedConnectionBackend>(directory.path());auto *fake=backend.get();fake->activeId="work";
        SavedConnectionService service(std::move(backend));auto *source=service.settings();
        source->setValue("Credential/Username","edited");
        if(!QFile::rename(path,path+".backup") || !QDir().mkdir(path))return false;
        blocked=!service.switchTo("target") && service.createAndSwitch("copy").isEmpty()
            && !service.renameCurrent("renamed") && !service.removeCurrentAndSwitchToDefault()
            && service.settings()==source && service.currentConnectionId()=="work" && fake->activeId=="work"
            && source->value("Credential/Username")=="edited" && fake->activeWrites==0
            && fake->creates==0 && fake->renames==0 && fake->removals==0;
        if(!QDir().rmdir(path) || !QFile::rename(path+".backup",path))return false;
    }
    QFile persisted(path);
    if (!persisted.open(QIODevice::ReadOnly)) return false;
    const auto contents = persisted.readAll();
    QSettings reopened(path,QSettings::IniFormat);
    if(!contents.contains("Username=edited") || !contents.contains("Ticket=retained") || !blocked || reopened.value("Credential/Username")!="edited" || reopened.value("OtherAccount/Ticket")!="retained") {
        qCritical()<<"source sync failure must preserve the selected profile and pending values before any backend mutation";return false;
    }
    return true;
}

bool rejectsMalformedAndNonFileTargets()
{
    QTemporaryDir directory;
    QSettings work(directory.filePath("work.ini"),QSettings::IniFormat);work.setValue("Credential/Username","alice");work.sync();
    auto backend=std::make_unique<FakeSavedConnectionBackend>(directory.path());auto *fake=backend.get();fake->activeId="work";
    SavedConnectionService service(std::move(backend));auto *source=service.settings();
    QFile broken(directory.filePath("broken.ini"));if(!broken.open(QIODevice::WriteOnly))return false;
    broken.write("[broken section\nCredential/Username=unexpected\n");broken.close();
    if(!QDir().mkdir(directory.filePath("folder.ini")))return false;
    const bool targetsRejected=!service.switchTo("broken") && !service.switchTo("broken") && !service.switchTo("folder");
    QFile defaults(directory.filePath("default.ini"));if(!defaults.open(QIODevice::WriteOnly|QIODevice::Truncate))return false;
    defaults.write("[broken section\n");defaults.close();
    if(!targetsRejected || service.removeCurrentAndSwitchToDefault() || service.settings()!=source
        || service.currentConnectionId()!="work" || fake->activeId!="work" || fake->activeWrites!=0 || fake->removals!=0
        || !QFileInfo::exists(directory.filePath("work.ini")) || source->value("Credential/Username")!="alice") {
        qCritical()<<"invalid target must not change selection or delete the current profile";return false;
    }
    return true;
}

bool managesCurrentProfileAsOneUnit()
{
    QTemporaryDir directory;
    auto backend = std::make_unique<FakeSavedConnectionBackend>(directory.path());
    FakeSavedConnectionBackend *fake = backend.get();
    SavedConnectionService service(std::move(backend));
    service.settings()->setValue("Credential/Username", "alice");
    service.settings()->setValue("JustConnect/ServerAddress", "vpn.example.invalid");
    service.settings()->setValue("JustConnect/AuthType", "httpsOauth2");
    service.settings()->sync();

    QTemporaryDir staging;
    QSettings draft(staging.filePath("draft.ini"),QSettings::IniFormat);
    draft.setValue("JustConnect/ServerAddress","vpn.new-campus.invalid");
    draft.sync();
    fake->allowActiveProfileChange = false;
    if (!service.createAndSwitch("blocked",draft.fileName()).isEmpty()
        || !QFileInfo::exists(draft.fileName())
        || service.currentConnectionId() != ""
        || QFileInfo::exists(fake->connectionPath("blocked")))
    {
        qCritical() << "failed activation left a created profile behind";
        return false;
    }
    fake->allowActiveProfileChange = true;

    if (!service.switchTo("missing"))
    {
        // Expected: missing profiles are rejected.
    }
    else
    {
        qCritical() << "missing profile was accepted";
        return false;
    }

    if (service.createAndSwitch("work") != "work"
        || service.currentConnectionId() != "work"
        || !service.settings()->allKeys().isEmpty())
    {
        qCritical() << "new connection inherited settings from the active connection";
        return false;
    }

    fake->allowActiveProfileChange = false;
    QSettings *workSettings = service.settings();
    if (service.renameCurrent("blocked")
        || service.currentConnectionId() != "work"
        || service.settings() != workSettings
        || !QFileInfo::exists(fake->connectionPath("work"))
        || QFileInfo::exists(fake->connectionPath("blocked")))
    {
        qCritical() << "failed activation did not roll back profile rename";
        return false;
    }
    fake->allowActiveProfileChange = true;

    if (!service.renameCurrent("renamed")
        || service.currentConnectionId() != "renamed")
    {
        qCritical() << "profile rename failed";
        return false;
    }

    QSettings *renamedSettings = service.settings();
    fake->allowActiveProfileChange = false;
    if (service.removeCurrentAndSwitchToDefault()
        || service.currentConnectionId() != "renamed"
        || service.settings() != renamedSettings
        || !QFileInfo::exists(fake->connectionPath("renamed"))
        || fake->activeId != "renamed")
    {
        qCritical() << "failed default activation changed the current profile";
        return false;
    }
    fake->allowActiveProfileChange = true;

    fake->allowProfileRemoval = false;
    if (service.removeCurrentAndSwitchToDefault()
        || service.currentConnectionId() != "renamed"
        || service.settings() != renamedSettings
        || !QFileInfo::exists(fake->connectionPath("renamed"))
        || fake->activeId != "renamed")
    {
        qCritical() << "failed removal changed the current profile";
        return false;
    }

    fake->allowProfileRemoval = true;
    fake->allowAutoStartSave = false;
    if (service.migrateAutoStartSetting(true) || fake->migratedAutoStart) return false;
    fake->allowAutoStartSave = true;
    if (!service.migrateAutoStartSetting(true) || !fake->migratedAutoStart
        || !service.removeCurrentAndSwitchToDefault()
        || !service.currentConnectionId().isEmpty())
    {
        qCritical() << "profile removal or global setting migration failed";
        return false;
    }
    return true;
}

bool acceptsCustomAsARegularProfileId()
{
    QTemporaryDir directory;
    auto backend = std::make_unique<FakeSavedConnectionBackend>(directory.path());
    FakeSavedConnectionBackend *fake = backend.get();
    SavedConnectionService service(std::move(backend));
    service.settings()->setValue("Credential/Username", "custom-user");
    service.settings()->sync();

    if (service.createAndSwitch("custom") != "custom"
        || service.usesOverrideConfiguration()
        || service.currentConnectionId() != "custom")
    {
        qCritical() << "custom profile creation failed";
        return false;
    }
    if (!service.renameCurrent("renamed")
        || service.currentConnectionId() != "renamed")
    {
        qCritical() << "custom profile rename failed";
        return false;
    }
    if (!service.removeCurrentAndSwitchToDefault())
    {
        qCritical() << "renamed custom profile removal failed";
        return false;
    }
    return fake->activeId.isEmpty();
}

bool savesOnlyPublicBatchesAndRollsBackFailures()
{
    QTemporaryDir directory;const auto path=directory.filePath("batch.ini");
    QSettings settings(path,QSettings::IniFormat);
    settings.setValue("Credential/Username","alice");settings.setValue("Common/ConfigVersion",8);
    settings.setValue("JustConnect/ExtraArguments","retained-until-commit");settings.setValue("OtherAccount/Ticket","retained");settings.sync();
    if (SavedConnectionService::writePublic(settings,{{"Credential/Password","plain"},{"Credential/Username","bob"}})
        || SavedConnectionService::writePublic(settings,{{"Common/ConfigVersion",999}})
        || settings.value("Credential/Username")!="alice" || settings.contains("Credential/Password")) return false;
    if (!QFile::rename(path,path+".backup") || !QDir().mkdir(path)) return false;
    const auto failed=SavedConnectionService::writePublic(settings,{{"Credential/Username","bob"},{"JustConnect/DNSTTL",123}});
    const bool rolledBack=!failed && settings.value("Credential/Username")=="alice" && !settings.contains("JustConnect/DNSTTL")
        && settings.value("Common/ConfigVersion")==8 && settings.value("JustConnect/ExtraArguments")=="retained-until-commit"
        && settings.value("OtherAccount/Ticket")=="retained";
    if (!QDir().rmdir(path) || !QFile::rename(path+".backup",path) || !rolledBack) return false;
    QSettings retry(path,QSettings::IniFormat);
    return SavedConnectionService::writePublic(retry,{{"Credential/Username","bob"},{"JustConnect/DNSTTL",123}})
        && retry.value("Credential/Username")=="bob" && retry.value("JustConnect/DNSTTL")==123
        && !retry.contains("JustConnect/ExtraArguments") && retry.value("OtherAccount/Ticket")=="retained";
}

bool switchesAwayFromAnOverrideNamedCustom()
{
    QTemporaryDir directory;
    const QString overridePath = directory.filePath("override.ini");
    const QString connectionsPath = directory.filePath("connections");
    QDir().mkpath(connectionsPath);
    {
        QSettings overrideSettings(overridePath, QSettings::IniFormat);
        overrideSettings.setValue("Credential/Username", "override-user");
        overrideSettings.sync();
    }

    auto backend = std::make_unique<FakeSavedConnectionBackend>(connectionsPath);
    FakeSavedConnectionBackend *fake = backend.get();
    SavedConnectionService service(std::move(backend), overridePath);

    if (!service.usesOverrideConfiguration()
        || service.createAndSwitch("custom") != "custom"
        || service.usesOverrideConfiguration()
        || service.currentConnectionId() != "custom"
        || service.settings()->fileName() != fake->connectionPath("custom")
        || fake->activeId != "custom")
    {
        qCritical() << "override configuration was confused with profile custom";
        return false;
    }
    return true;
}
}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    return rejectsUnsavedSourceBeforeChangingProfiles() && rejectsMalformedAndNonFileTargets()
        && savesOnlyPublicBatchesAndRollsBackFailures()
        && managesCurrentProfileAsOneUnit()
        && acceptsCustomAsARegularProfileId()
        && switchesAwayFromAnOverrideNamedCustom() ? 0 : 1;
}
