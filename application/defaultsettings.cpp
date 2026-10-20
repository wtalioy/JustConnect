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
        {"Credential/Password", ""},
        {"Credential/TOTPSecret", ""},

        {"Common/ConnectAfterStart", false},
        {"Common/CheckUpdateAfterStart", false},
        {"Common/AutoSetProxy", false},
        {"Common/ReconnectTime", 1},
        {"Common/AutoReconnect", false},
        {"Common/SystemProxyBypass", ""},

        {"Common/NeedsConfiguration", false},
        {"JustConnect/ProfileKind", "Custom"},
        {"JustConnect/ServerAddress", ""},
        {"JustConnect/ServerPort", 443},
        {"JustConnect/TLSVerify", true},
        {"JustConnect/TLSCAPEM", ""},
        {"JustConnect/SecondaryDNS", ""},
        {"JustConnect/LocalDNSServer", ""},
        {"JustConnect/DNSTTL", 3600},
        {"JustConnect/SOCKS5Port", 11080},
        {"JustConnect/HTTPPort", 11081},

        {"JustConnect/LoginDomain", ""},
        {"JustConnect/AuthType", "psw"},
        {"JustConnect/AuthID", ""},
        {"JustConnect/AuthSubType", ""},
        {"JustConnect/LoginURL", ""},
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

bool DefaultSettings::exportTo(const QSettings &settings,const QString &path)
{
    const QFileInfo source(settings.fileName()), destination(path);
    if (destination.absoluteFilePath()==source.absoluteFilePath()
        || (!destination.canonicalFilePath().isEmpty() && destination.canonicalFilePath()==source.canonicalFilePath()))
        return false;
    QTemporaryDir folder;
    if (!folder.isValid()) return false;
    QSettings output(folder.filePath("export.ini"),QSettings::IniFormat);
    for (auto it=defaults().cbegin();it!=defaults().cend();++it) {
        const auto &key=it.key();
        // Export only owned public fields; URL previews may contain session tokens.
        if (key=="Credential/Password" || key=="Credential/TOTPSecret" || key=="JustConnect/LoginURL") continue;
        if (settings.contains(key)) output.setValue(key,settings.value(key));
    }
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
