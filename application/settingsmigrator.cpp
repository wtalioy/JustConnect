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
    if (configVersion == 4 && !settings.contains("JustConnect/Protocol"))
    {
        settings.setValue("JustConnect/Protocol", "easyconnect");
    }
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
    if (previous.toInt() > ApplicationConstants::ConfigVersion) return true;
    settings.setValue("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
    settings.sync();
    if (settings.status() == QSettings::NoError) return true;
    if (previous.isValid()) settings.setValue("Common/ConfigVersion", previous);
    else settings.remove("Common/ConfigVersion");
    return false;
}
