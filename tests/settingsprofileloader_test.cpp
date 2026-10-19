#include <QCoreApplication>
#include <QDebug>
#include <QSettings>
#include <QTemporaryDir>

#include "infrastructure/settings/settingsprofileloader.h"

namespace
{
bool loadsSettingsIntoTypedProfile()
{
    QTemporaryDir directory;
    if (!directory.isValid())
    {
        qCritical() << "Unable to create temporary directory";
        return false;
    }

    QSettings settings(directory.filePath("profile.ini"), QSettings::IniFormat);
    settings.setValue("Credential/TOTPSecret", "totp");
    settings.setValue("Credential/CertFile", "/tmp/client.p12");
    settings.setValue(
        "Credential/CertPassword",
        QString(QStringLiteral("cert-password").toUtf8().toBase64())
    );
    settings.setValue("JustConnect/Protocol", "atrust");
    settings.setValue("JustConnect/AuthType", "cas");
    settings.setValue("JustConnect/LoginDomain", "domain");
    settings.setValue("JustConnect/PhoneCountryCode", "86");
    settings.setValue("JustConnect/PhoneNumber", "123456");
    settings.setValue("JustConnect/ServerAddress", "vpn.example.edu");
    settings.setValue("JustConnect/ServerPort", 8443);
    settings.setValue("JustConnect/DNS", "10.0.0.1");
    settings.setValue("JustConnect/DNSAuto", false);
    settings.setValue("JustConnect/SecondaryDNS", "10.0.0.2");
    settings.setValue("JustConnect/LocalDNSServer", "223.5.5.5:53");
    settings.setValue("JustConnect/DNSServerBind", "127.0.0.1:5353");
    settings.setValue("JustConnect/DNSTTL", 60);
    settings.setValue("JustConnect/DisableRemoteDNS", true);
    settings.setValue("JustConnect/CustomDNS", "example.org=1.1.1.1");
    settings.setValue("JustConnect/OutsideAccess", true);
    settings.setValue("JustConnect/SOCKS5Port", 1080);
    settings.setValue("JustConnect/HTTPPort", 1081);
    settings.setValue("JustConnect/ShadowsocksURL", "ss://url");
    settings.setValue("JustConnect/DialDirectProxy", "http://direct");
    settings.setValue("JustConnect/ProxyAll", true);
    settings.setValue("JustConnect/CustomProxyDomain", "example.org");
    settings.setValue("JustConnect/TUNMode", true);
    settings.setValue("JustConnect/AddRoute", true);
    settings.setValue("JustConnect/DNSHijack", true);
    settings.setValue("JustConnect/FakeIP", true);
    settings.setValue("JustConnect/TCPTunnelMode", true);
    settings.setValue("JustConnect/TCPPortForwarding", "tcp-forward");
    settings.setValue("JustConnect/UDPPortForwarding", "udp-forward");
    settings.setValue("JustConnect/UpdateBestNodesInterval", 30);
    settings.setValue("JustConnect/CredentialsAsArguments", true);
    settings.setValue("JustConnect/MultiLine", false);
    settings.setValue("JustConnect/KeepAlive", false);
    settings.setValue("JustConnect/KeepAliveURL", "https://keepalive");
    settings.setValue("JustConnect/BindInterface", "en0");
    settings.setValue("JustConnect/AutoDetectInterface", true);
    settings.setValue("JustConnect/SkipDomainResource", true);
    settings.setValue("JustConnect/DisableServerConfig", true);
    settings.setValue("JustConnect/Debug", true);
    settings.setValue("JustConnect/DebugPCAP", true);
    settings.setValue("JustConnect/DebugTLSLog", true);
    settings.setValue("JustConnect/ExtraArguments", "-foo bar");

    const ConnectionProfile profile =
        SettingsProfileLoader::load(settings, "campus", "alice", "secret");

    const bool passed =
        profile.profileId == "campus"
        && profile.credentials.username == "alice"
        && profile.credentials.password == "secret"
        && profile.credentials.totpSecret == "totp"
        && profile.credentials.certFile.isEmpty()
        && profile.credentials.certPassword.isEmpty()
        && profile.credentials.passAsArguments
        && profile.endpoint.protocol == "atrust"
        && profile.endpoint.authType == "cas"
        && profile.endpoint.loginDomain == "domain"
        && profile.endpoint.phone == "86-123456"
        && profile.endpoint.server == "vpn.example.edu"
        && profile.endpoint.port == 8443
        && profile.dns.primary == "10.0.0.1"
        && !profile.dns.automatic
        && profile.dns.secondary == "10.0.0.2"
        && profile.dns.ttl == 60
        && profile.dns.disableRemoteDns
        && profile.dns.custom == "example.org=1.1.1.1"
        && profile.dns.localDnsServer == "223.5.5.5:53"
        && profile.dns.dnsServerBind == "127.0.0.1:5353"
        && profile.proxy.socksBind == "[::]:1080"
        && profile.proxy.httpBind == "[::]:1081"
        && profile.proxy.shadowsocksUrl == "ss://url"
        && profile.proxy.dialDirectProxy == "http://direct"
        && profile.proxy.proxyAll
        && profile.proxy.customDomains == "example.org"
        && profile.tunnel.tunMode
        && profile.tunnel.addRoute
        && profile.tunnel.dnsHijack
        && profile.tunnel.fakeIp
        && profile.tunnel.tcpTunnelMode
        && profile.tunnel.tcpPortForwarding == "tcp-forward"
        && profile.tunnel.udpPortForwarding == "udp-forward"
        && profile.behavior.updateBestNodesInterval == 30
        && profile.behavior.disableMultiLine
        && profile.behavior.disableKeepAlive
        && profile.behavior.keepAliveUrl == "https://keepalive"
        && profile.behavior.bindInterface == "en0"
        && profile.behavior.autoDetectInterface
        && profile.behavior.skipDomainResource
        && profile.behavior.disableServerConfig
        && profile.debug.detailedOutput
        && profile.debug.capturePcap
        && profile.debug.exportTlsKeys
        && profile.extraArguments == "-foo bar";

    if (!passed)
    {
        qCritical() << "loadsSettingsIntoTypedProfile failed";
    }
    return passed;
}

bool usesCompatibleDefaults()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("empty.ini"), QSettings::IniFormat);

    const ConnectionProfile profile = SettingsProfileLoader::load(settings, "", "", "");
    const bool passed =
        profile.behavior.updateBestNodesInterval == 300
        && !profile.credentials.passAsArguments
        && profile.behavior.disableMultiLine
        && profile.behavior.disableKeepAlive
        && profile.dns.localDnsServer.isEmpty()
        && profile.dns.dnsServerBind.isEmpty()
        && !profile.debug.detailedOutput
        && !profile.debug.capturePcap
        && !profile.debug.exportTlsKeys
        && profile.proxy.socksBind == "127.0.0.1:0"
        && profile.proxy.httpBind == "127.0.0.1:0";
    if (!passed)
    {
        qCritical() << "usesCompatibleDefaults failed";
    }
    return passed;
}

bool respectsEasyConnectAuthenticationMode()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath("easyconnect.ini"), QSettings::IniFormat);
    settings.setValue("JustConnect/Protocol", "easyconnect");
    settings.setValue("Credential/CertFile", "/tmp/client.p12");
    settings.setValue(
        "Credential/CertPassword",
        QString(QStringLiteral("cert-password").toUtf8().toBase64())
    );

    settings.setValue("JustConnect/EasyConnectAuthType", "password");
    const ConnectionProfile passwordProfile =
        SettingsProfileLoader::load(settings, "", "alice", "secret");
    if (!passwordProfile.credentials.certFile.isEmpty()
        || !passwordProfile.credentials.certPassword.isEmpty())
    {
        qCritical() << "password mode kept certificate credentials";
        return false;
    }

    settings.setValue("JustConnect/EasyConnectAuthType", "certificate");
    const ConnectionProfile certificateProfile =
        SettingsProfileLoader::load(settings, "", "", "");
    const bool passed =
        certificateProfile.credentials.certFile == "/tmp/client.p12"
        && certificateProfile.credentials.certPassword == "cert-password";
    if (!passed)
    {
        qCritical() << "certificate mode did not load certificate credentials";
    }
    return passed;
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return loadsSettingsIntoTypedProfile()
        && usesCompatibleDefaults()
        && respectsEasyConnectAuthenticationMode() ? 0 : 1;
}
