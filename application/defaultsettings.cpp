#include "application/defaultsettings.h"

#include <QSettings>

#include "application/applicationconstants.h"

void DefaultSettings::reset(QSettings &settings)
{
    settings.setValue("Credential/Username", "");
    settings.setValue("Credential/Password", "");
    settings.setValue("Credential/TOTPSecret", "");

    settings.setValue("Common/ConnectAfterStart", false);
    settings.setValue("Common/CheckUpdateAfterStart", false);
    settings.setValue("Common/AutoSetProxy", false);
    settings.setValue("Common/ReconnectTime", 1);
    settings.setValue("Common/AutoReconnect", false);
    settings.setValue("Common/SystemProxyBypass", "");

    settings.setValue("JustConnect/ServerAddress", "");
    settings.setValue("JustConnect/ServerPort", 443);
    settings.setValue("JustConnect/DNS", "");
    settings.setValue("JustConnect/DNSAuto", true);
    settings.setValue("JustConnect/SecondaryDNS", "");
    settings.setValue("JustConnect/LocalDNSServer", "");
    settings.setValue("JustConnect/DNSServerBind", "");
    settings.setValue("JustConnect/DNSTTL", 3600);
    settings.setValue("JustConnect/SOCKS5Port", 11080);
    settings.setValue("JustConnect/HTTPPort", 11081);
    settings.setValue("JustConnect/ShadowsocksURL", "");
    settings.setValue("JustConnect/DialDirectProxy", "");
    settings.setValue("JustConnect/UpdateBestNodesInterval", 300);

    settings.setValue("JustConnect/Protocol", "atrust");
    settings.setValue("JustConnect/EasyConnectAuthType", "password");
    settings.setValue("JustConnect/LoginDomain", "");
    settings.setValue("JustConnect/AuthType", "psw");
    settings.setValue("JustConnect/LoginURL", "");
    settings.setValue("JustConnect/PhoneCountryCode", "86");
    settings.setValue("JustConnect/PhoneNumber", "");

    settings.setValue("JustConnect/MultiLine", false);
    settings.setValue("JustConnect/KeepAlive", false);
    settings.setValue("JustConnect/KeepAliveURL", "");
    settings.setValue("JustConnect/BindInterface", "");
    settings.setValue("JustConnect/OutsideAccess", false);
    settings.setValue("JustConnect/SkipDomainResource", false);
    settings.setValue("JustConnect/DisableServerConfig", false);
    settings.setValue("JustConnect/ProxyAll", false);
    settings.setValue("JustConnect/DisableRemoteDNS", false);
    settings.setValue("JustConnect/Debug", false);
    settings.setValue("JustConnect/DebugPCAP", false);
    settings.setValue("JustConnect/DebugTLSLog", false);

    settings.setValue("JustConnect/TUNMode", false);
    settings.setValue("JustConnect/AddRoute", false);
    settings.setValue("JustConnect/DNSHijack", false);
    settings.setValue("JustConnect/FakeIP", false);
    settings.setValue("JustConnect/TCPTunnelMode", false);
    settings.setValue("JustConnect/AutoDetectInterface", false);

    settings.setValue("JustConnect/TCPPortForwarding", "");
    settings.setValue("JustConnect/UDPPortForwarding", "");
    settings.setValue("JustConnect/CustomDNS", "");
    settings.setValue("JustConnect/CustomProxyDomain", "");
    settings.setValue("JustConnect/ExtraArguments", "");

    settings.setValue("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
}
