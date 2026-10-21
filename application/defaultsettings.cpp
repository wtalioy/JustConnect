#include "application/defaultsettings.h"

#include <QSettings>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryDir>
#include <QVariant>

#include "application/applicationconstants.h"

namespace {
const QVariantMap &defaults()
{
    static const QVariantMap values{
        {"Credential/Username", ""},
        {DefaultSettings::RememberAuthentication, false},

        {"Common/ConnectAfterStart", false},
        {"Common/CheckUpdateAfterStart", false},
        {"Common/AutoSetProxy", false},
        {"Common/ReconnectTime", 1},
        {"Common/AutoReconnect", false},
        {"Common/SystemProxyBypass", ""},
        {"Common/SuppressProxyOverrideWarning", false},

        {"Common/NeedsConfiguration", false},
        {"JustConnect/ProfileKind", "Custom"},
        {"JustConnect/ServerAddress", ""},
        {"JustConnect/ServerPort", 443},
        {"JustConnect/TLSVerify", true},
        {"JustConnect/TLSCAPEM", ""},
        {"JustConnect/AllowUnverifiedNodes", false},
        {"JustConnect/SecondaryDNS", ""},
        {"JustConnect/LocalDNSServer", ""},
        {"JustConnect/DNSTTL", 3600},
        {"JustConnect/SOCKS5Port", 11080},
        {"JustConnect/HTTPPort", 11081},
        {"JustConnect/KeepAliveMode", "auto"},
        {"JustConnect/KeepAliveURL", ""},

        {"JustConnect/LoginDomain", ""},
        {"JustConnect/AuthType", "psw"},
        {"JustConnect/AuthID", ""},
        {"JustConnect/AuthSubType", ""},
        {"JustConnect/PhoneCountryCode", "86"},
        {"JustConnect/PhoneNumber", ""},

        {"JustConnect/BindInterface", ""},
        {"JustConnect/DisableRemoteDNS", false},

        {"JustConnect/AutoDetectInterface", false},

    };
    return values;
}
void apply(QSettings &settings, bool overwrite)
{
    for (auto it=defaults().cbegin();it!=defaults().cend();++it)
        if (overwrite || !settings.contains(it.key())) settings.setValue(it.key(),it.value());
    if (overwrite) settings.setValue("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
}
}

void DefaultSettings::reset(QSettings &settings) { apply(settings, true); }
void DefaultSettings::initialize(QSettings &settings) { apply(settings, false); }

bool DefaultSettings::isPublicKey(const QString &key)
{
    return key=="Common/ConfigVersion" || defaults().contains(key);
}

QVariantMap DefaultSettings::publicValues(const QSettings &settings)
{
    QVariantMap values;
    for (const auto &key:settings.allKeys()) if (isPublicKey(key)) values.insert(key,settings.value(key));
    return values;
}

bool DefaultSettings::exportTo(const QSettings &settings,const QString &path)
{
    const QFileInfo source(settings.fileName()), destination(path);
    if (destination.absoluteFilePath()==source.absoluteFilePath()
        || (!destination.canonicalFilePath().isEmpty() && destination.canonicalFilePath()==source.canonicalFilePath()))
        return false;
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    QSettings output(folder.filePath("export.ini"),QSettings::IniFormat);
    const auto values=publicValues(settings);
    for (auto it=values.cbegin();it!=values.cend();++it) output.setValue(it.key(),it.value());
    output.setValue("Common/ConfigVersion",ApplicationConstants::ConfigVersion);
    output.sync();
    if (output.status()!=QSettings::NoError) return false;
    QFile file(output.fileName());
    if (!file.open(QIODevice::ReadOnly)) return false;
    const auto bytes=file.readAll();
    if (file.error()!=QFileDevice::NoError) return false;
    QSaveFile target(path);
    return target.open(QIODevice::WriteOnly) && target.write(bytes)==bytes.size() && target.commit();
}
