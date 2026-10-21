#ifndef DEFAULTSETTINGS_H
#define DEFAULTSETTINGS_H

#include <QVariantMap>
class QSettings;
class QString;

namespace DefaultSettings
{
inline constexpr const char *RememberAuthentication="JustConnect/RememberAuthentication";
void reset(QSettings &settings);
void initialize(QSettings &settings);
QVariantMap publicValues(const QSettings &settings);
bool isPublicKey(const QString &key);
bool exportTo(const QSettings &settings,const QString &path);
}

#endif // DEFAULTSETTINGS_H
