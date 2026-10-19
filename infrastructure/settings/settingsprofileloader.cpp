#include "settingsprofileloader.h"

ConnectionProfile SettingsProfileLoader::load(
    const QSettings &settings,
    const QString &profileId,
    const QString &username,
    const QString &password
)
{
    ConnectionProfile profile;
    profile.profileId = profileId;
    const QString easyconnectAuthType = settings.value(
        "JustConnect/EasyConnectAuthType",
        settings.value("Credential/CertFile", "").toString().isEmpty()
            ? "password"
            : "certificate"
    ).toString();
    const bool useCertificate =
        settings.value("JustConnect/Protocol").toString() == "easyconnect"
        && easyconnectAuthType == "certificate";
    profile.credentials = {
        username,
        password,
        settings.value("Credential/TOTPSecret").toString(),
        useCertificate
            ? settings.value("Credential/CertFile", "").toString()
            : QString(),
        useCertificate
            ? QByteArray::fromBase64(
                  settings.value("Credential/CertPassword", "").toByteArray()
              )
            : QString(),
        settings.value("JustConnect/CredentialsAsArguments", false).toBool()
    };

    const QString countryCode = settings.value("JustConnect/PhoneCountryCode").toString();
    const QString phoneNumber = settings.value("JustConnect/PhoneNumber").toString();
    const QString phone = !countryCode.isEmpty() && !phoneNumber.isEmpty()
        ? countryCode + "-" + phoneNumber
        : QString();
    profile.endpoint = {
        settings.value("JustConnect/Protocol").toString(),
        settings.value("JustConnect/AuthType").toString(),
        settings.value("JustConnect/LoginDomain").toString(),
        phone,
        settings.value("JustConnect/ServerAddress").toString(),
        settings.value("JustConnect/ServerPort").toInt()
    };

    profile.dns = {
        settings.value("JustConnect/DNS").toString(),
        settings.value("JustConnect/DNSAuto").toBool(),
        settings.value("JustConnect/SecondaryDNS").toString(),
        settings.value("JustConnect/DNSTTL").toInt(),
        settings.value("JustConnect/DisableRemoteDNS").toBool(),
        settings.value("JustConnect/CustomDNS", "").toString(),
        settings.value("JustConnect/LocalDNSServer", "").toString(),
        settings.value("JustConnect/DNSServerBind", "").toString()
    };

    const QString bindPrefix = settings.value("JustConnect/OutsideAccess", false).toBool()
        ? "[::]:"
        : "127.0.0.1:";
    profile.proxy = {
        bindPrefix + QString::number(settings.value("JustConnect/SOCKS5Port").toInt()),
        bindPrefix + QString::number(settings.value("JustConnect/HTTPPort").toInt()),
        settings.value("JustConnect/ShadowsocksURL").toString(),
        settings.value("JustConnect/DialDirectProxy").toString(),
        settings.value("JustConnect/ProxyAll").toBool(),
        settings.value("JustConnect/CustomProxyDomain", "").toString()
    };

    profile.tunnel = {
        settings.value("JustConnect/TUNMode").toBool(),
        settings.value("JustConnect/AddRoute").toBool(),
        settings.value("JustConnect/DNSHijack").toBool(),
        settings.value("JustConnect/FakeIP").toBool(),
        settings.value("JustConnect/TCPTunnelMode").toBool(),
        settings.value("JustConnect/TCPPortForwarding").toString(),
        settings.value("JustConnect/UDPPortForwarding").toString()
    };

    profile.behavior = {
        settings.value("JustConnect/UpdateBestNodesInterval", 300).toInt(),
        !settings.value("JustConnect/MultiLine").toBool(),
        !settings.value("JustConnect/KeepAlive").toBool(),
        settings.value("JustConnect/KeepAliveURL", "").toString(),
        settings.value("JustConnect/BindInterface", "").toString(),
        settings.value("JustConnect/AutoDetectInterface", false).toBool(),
        settings.value("JustConnect/SkipDomainResource").toBool(),
        settings.value("JustConnect/DisableServerConfig").toBool()
    };

    profile.debug = {
        settings.value("JustConnect/Debug").toBool(),
        settings.value("JustConnect/DebugPCAP", false).toBool(),
        settings.value("JustConnect/DebugTLSLog", false).toBool()
    };

    profile.extraArguments = settings.value("JustConnect/ExtraArguments", "").toString();
    return profile;
}
