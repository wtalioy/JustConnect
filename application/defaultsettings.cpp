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

    set("JustConnect/ServerAddress", "");
    set("JustConnect/ServerPort", 443);
    set("JustConnect/DNS", "");
    set("JustConnect/DNSAuto", true);
    set("JustConnect/SecondaryDNS", "");
    set("JustConnect/LocalDNSServer", "");
    set("JustConnect/DNSServerBind", "");
    set("JustConnect/DNSTTL", 3600);
    set("JustConnect/SOCKS5Port", 11080);
    set("JustConnect/HTTPPort", 11081);
    set("JustConnect/ShadowsocksURL", "");
    set("JustConnect/DialDirectProxy", "");
    set("JustConnect/UpdateBestNodesInterval", 300);

    set("JustConnect/Protocol", "atrust");
    set("JustConnect/EasyConnectAuthType", "password");
    set("JustConnect/LoginDomain", "");
    set("JustConnect/AuthType", "psw");
    set("JustConnect/LoginURL", "");
    set("JustConnect/PhoneCountryCode", "86");
    set("JustConnect/PhoneNumber", "");

    set("JustConnect/MultiLine", false);
    set("JustConnect/KeepAlive", false);
    set("JustConnect/KeepAliveURL", "");
    set("JustConnect/BindInterface", "");
    set("JustConnect/OutsideAccess", false);
    set("JustConnect/SkipDomainResource", false);
    set("JustConnect/DisableServerConfig", false);
    set("JustConnect/ProxyAll", false);
    set("JustConnect/DisableRemoteDNS", false);
    set("JustConnect/Debug", false);
    set("JustConnect/DebugPCAP", false);
    set("JustConnect/DebugTLSLog", false);

    set("JustConnect/TUNMode", false);
    set("JustConnect/AddRoute", false);
    set("JustConnect/DNSHijack", false);
    set("JustConnect/FakeIP", false);
    set("JustConnect/TCPTunnelMode", false);
    set("JustConnect/AutoDetectInterface", false);

    set("JustConnect/TCPPortForwarding", "");
    set("JustConnect/UDPPortForwarding", "");
    set("JustConnect/CustomDNS", "");
    set("JustConnect/CustomProxyDomain", "");
    set("JustConnect/ExtraArguments", "");

    if (overwrite) set("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
}
}

void DefaultSettings::reset(QSettings &settings) { apply(settings, true); }
void DefaultSettings::initialize(QSettings &settings) { apply(settings, false); }
