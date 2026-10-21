#include "settingsmigrator.h"

#include <QDebug>
#include <QSettings>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include "application/applicationconstants.h"
#include "application/defaultsettings.h"

namespace {
QString legacyTarget(const QString &key)
{
    return "JustConnect/" + (key=="DisableZJUDNS" ? QString("DisableRemoteDNS") : key);
}
}

bool SettingsMigrator::readableFile(const QString &path)
{
    // QSettings caches parsed INI data without retaining its format error for later instances.
    if (!QFileInfo(path).isFile()) return false;
    QTemporaryDir snapshot;
    if (!snapshot.isValid()) return false;
    QFile input(path);
    if (!input.open(QIODevice::ReadOnly)) return false;
    const auto bytes=input.readAll();
    if (input.error()!=QFileDevice::NoError) return false;
    QFile copy(snapshot.filePath("input.ini"));
    if (!copy.open(QIODevice::WriteOnly|QIODevice::NewOnly,QFile::ReadOwner|QFile::WriteOwner)
        || copy.write(bytes)!=bytes.size() || !copy.flush()) return false;
    copy.close();
    QSettings original(copy.fileName(),QSettings::IniFormat);
    original.allKeys();
    return original.status()==QSettings::NoError;
}

SettingsMigrationAction SettingsMigrator::prepare(QSettings &settings)
{
    if (settings.status()!=QSettings::NoError
        || (QFileInfo::exists(settings.fileName()) && !readableFile(settings.fileName()))) return SettingsMigrationAction::Failed;
    settings.beginGroup("ZJUConnect");
    const QStringList previousKeys = settings.allKeys();
    settings.endGroup();
    for (const QString &key : previousKeys)
    {
        if (key == "ZJUDefault")
        {
            continue;
        }
        const QString target = legacyTarget(key);
        if (!settings.contains(target))
        {
            settings.setValue(target, settings.value("ZJUConnect/" + key));
        }
    }
    // Save copied values before removing the legacy group.
    if (!previousKeys.isEmpty())
    {
        settings.sync();
        if (settings.status() == QSettings::NoError)
        {
            settings.remove("ZJUConnect");
            settings.sync();
        }
        else
        {
            qWarning() << "配置分组改名未能保存，已保留原配置";
            return SettingsMigrationAction::Failed;
        }
    }

    const int configVersion = settings.value("Common/ConfigVersion", -1).toInt();
    const auto protocol = settings.value("JustConnect/Protocol").toString();
    if ((configVersion == 4 && protocol.isEmpty())
        || (!protocol.isEmpty() && protocol.compare("atrust",Qt::CaseInsensitive) != 0))
        settings.setValue("Common/NeedsConfiguration",true);
    if (!settings.contains("JustConnect/ProfileKind"))
        settings.setValue("JustConnect/ProfileKind",
            settings.value("JustConnect/ServerAddress").toString() == ApplicationConstants::FudanServer
            && settings.value("JustConnect/ServerPort",443).toInt() == ApplicationConstants::FudanPort ? "Fudan" : "Custom");
    DefaultSettings::initialize(settings);
    if (configVersion == 6)
    {
        return SettingsMigrationAction::MigrateAutoStart;
    }
    return SettingsMigrationAction::None;
}

bool SettingsMigrator::finish(QSettings &settings)
{
    if (settings.status()!=QSettings::NoError
        || (QFileInfo::exists(settings.fileName()) && !readableFile(settings.fileName()))) return false;
    const auto previous = settings.value("Common/ConfigVersion");
    QVariantMap removed;
    if (previous.toInt() <= ApplicationConstants::ConfigVersion) {
        const QStringList obsolete{
            "JustConnect/DNS",
            "JustConnect/DNSAuto",
            "JustConnect/DNSServerBind",
            "JustConnect/ShadowsocksURL",
            "JustConnect/DialDirectProxy",
            "JustConnect/UpdateBestNodesInterval",
            "JustConnect/Protocol",
            "JustConnect/LoginURL",
            "JustConnect/EasyConnectAuthType",
            "JustConnect/MultiLine",
            "JustConnect/KeepAlive",
            "JustConnect/KeepAliveURL",
            "JustConnect/OutsideAccess",
            "JustConnect/SkipDomainResource",
            "JustConnect/DisableServerConfig",
            "JustConnect/ProxyAll",
            "JustConnect/Debug",
            "JustConnect/DebugPCAP",
            "JustConnect/DebugTLSLog",
            "JustConnect/TUNMode",
            "JustConnect/AddRoute",
            "JustConnect/DNSHijack",
            "JustConnect/FakeIP",
            "JustConnect/TCPTunnelMode",
            "JustConnect/TCPPortForwarding",
            "JustConnect/UDPPortForwarding",
            "JustConnect/CustomDNS",
            "JustConnect/CustomProxyDomain",
            "JustConnect/ExtraArguments",
            "Credential/CertFile",
            "Credential/CertPassword",
            "Common/AutoStart"
        };
        for (const auto &key:obsolete) {
            if (settings.contains(key)) removed.insert(key,settings.value(key));
            settings.remove(key);
        }
        settings.setValue("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
    }
    settings.sync();
    if (settings.status() == QSettings::NoError) return true;
    for (auto it=removed.cbegin();it!=removed.cend();++it) settings.setValue(it.key(),it.value());
    if (previous.isValid()) settings.setValue("Common/ConfigVersion", previous);
    else settings.remove("Common/ConfigVersion");
    return false;
}

bool SettingsMigrator::publicDraft(const QSettings &source,QSettings &draft)
{
    if (source.status()!=QSettings::NoError || draft.status()!=QSettings::NoError || !draft.allKeys().isEmpty()
        || (QFileInfo::exists(source.fileName()) && !readableFile(source.fileName()))) return false;
    for (const auto &key:source.allKeys()) {
        const auto current=key.startsWith("ZJUConnect/") ? legacyTarget(key.mid(11)) : key;
        // Protocol is migration input, then removed at the public-data boundary.
        if (DefaultSettings::isPublicKey(current) || current=="JustConnect/Protocol") draft.setValue(key,source.value(key));
    }
    if (source.status()!=QSettings::NoError || prepare(draft)==SettingsMigrationAction::Failed || !finish(draft)) return false;
    for (const auto &key:draft.allKeys()) if (!DefaultSettings::isPublicKey(key)) draft.remove(key);
    draft.sync();
    return draft.status()==QSettings::NoError;
}
