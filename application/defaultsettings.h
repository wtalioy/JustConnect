#ifndef DEFAULTSETTINGS_H
#define DEFAULTSETTINGS_H

#include <QVariantMap>
class QSettings;
class QString;

namespace DefaultSettings
{
inline constexpr const char *RememberAuthentication="JustConnect/RememberAuthentication";
inline constexpr const char *DomainDnsRules="JustConnect/DomainDNSRules";
const QVariantMap &builtInConnection();
bool isBuiltInConnection(const QSettings &settings);
void reset(QSettings &settings);
void initialize(QSettings &settings);
void applyBuiltInConnection(QSettings &settings);
QVariantMap publicValues(const QSettings &settings);
bool isPublicKey(const QString &key);
bool exportTo(const QSettings &settings,const QString &path);
}

#endif // DEFAULTSETTINGS_H
