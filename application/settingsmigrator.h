#ifndef SETTINGSMIGRATOR_H
#define SETTINGSMIGRATOR_H

class QSettings;

enum class SettingsMigrationAction
{
    None,
    MigrateAutoStart,
    Failed
};

class SettingsMigrator
{
public:
    static SettingsMigrationAction prepare(QSettings &settings);
    static bool finish(QSettings &settings);
};

#endif // SETTINGSMIGRATOR_H
