#ifndef SETTINGSMIGRATOR_H
#define SETTINGSMIGRATOR_H

class QSettings;
class QString;

enum class SettingsMigrationAction
{
    None,
    MigrateAutoStart,
    Failed
};

class SettingsMigrator
{
public:
    static bool readableFile(const QString &path);
    static SettingsMigrationAction prepare(QSettings &settings);
    static bool finish(QSettings &settings);
    static bool publicDraft(const QSettings &source,QSettings &draft);
};

#endif // SETTINGSMIGRATOR_H
