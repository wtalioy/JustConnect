#ifndef SETTINGSPROFILELOADER_H
#define SETTINGSPROFILELOADER_H

#include <QSettings>

#include "core/connectionprofile.h"

class SettingsProfileLoader
{
public:
    static ConnectionProfile load(const QSettings &settings);
};

#endif // SETTINGSPROFILELOADER_H
