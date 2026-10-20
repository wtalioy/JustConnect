#include "application/defaultsettings.h"

#include <QSettings>
#include <QVariant>

#include "application/applicationconstants.h"

namespace {
void apply(QSettings &settings, bool overwrite)
{
    const auto set = [&](const QString &key, const QVariant &value) {
        if (overwrite || !settings.contains(key)) settings.setValue(key, value);
    };
    set("Credential/Username", "");
    set("Credential/Password", "");
    set("Credential/TOTPSecret", "");

    set("Common/ConnectAfterStart", false);
    set("Common/CheckUpdateAfterStart", false);
    set("Common/AutoSetProxy", false);
    set("Common/ReconnectTime", 1);
    set("Common/AutoReconnect", false);
    set("Common/SystemProxyBypass", "");

    set("Common/NeedsConfiguration", false);
    set("JustConnect/ProfileKind", "Custom");
    set("JustConnect/ServerAddress", "");
    set("JustConnect/ServerPort", 443);
    set("JustConnect/SecondaryDNS", "");
    set("JustConnect/LocalDNSServer", "");
    set("JustConnect/DNSTTL", 3600);
    set("JustConnect/SOCKS5Port", 11080);
    set("JustConnect/HTTPPort", 11081);

    set("JustConnect/LoginDomain", "");
    set("JustConnect/AuthType", "psw");
    set("JustConnect/LoginURL", "");
    set("JustConnect/PhoneCountryCode", "86");
    set("JustConnect/PhoneNumber", "");

    set("JustConnect/BindInterface", "");
    set("JustConnect/DisableRemoteDNS", false);

    set("JustConnect/AutoDetectInterface", false);

    if (overwrite) set("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
}
}

void DefaultSettings::reset(QSettings &settings) { apply(settings, true); }
void DefaultSettings::initialize(QSettings &settings) { apply(settings, false); }
