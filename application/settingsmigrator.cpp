#include "settingsmigrator.h"

#include <QDebug>
#include <QSettings>

#include "application/applicationconstants.h"
#include "application/defaultsettings.h"

SettingsMigrationAction SettingsMigrator::prepare(QSettings &settings)
{
    settings.beginGroup("ZJUConnect");
    const QStringList previousKeys = settings.allKeys();
    settings.endGroup();
    for (const QString &key : previousKeys)
    {
        if (key == "ZJUDefault")
        {
            continue;
        }
        const QString renamedKey = key == "DisableZJUDNS" ? "DisableRemoteDNS" : key;
        const QString target = "JustConnect/" + renamedKey;
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
