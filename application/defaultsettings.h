#ifndef DEFAULTSETTINGS_H
#define DEFAULTSETTINGS_H

class QSettings;
class QString;

namespace DefaultSettings
{
void reset(QSettings &settings);
void initialize(QSettings &settings);
bool exportTo(const QSettings &settings,const QString &path);
}

#endif // DEFAULTSETTINGS_H
