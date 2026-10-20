#include "settingsprofileloader.h"

ConnectionProfile SettingsProfileLoader::load(const QSettings &settings) {
    ConnectionProfile p;
    p.tls.verify=settings.value("JustConnect/TLSVerify",true).toBool();
    p.tls.caPem=settings.value("JustConnect/TLSCAPEM").toString();
    p.credentials.username=settings.value("Credential/Username").toString();
    p.endpoint.authId=settings.value("JustConnect/AuthID").toString();
    p.endpoint.authSubType=settings.value("JustConnect/AuthSubType").toString();
    p.endpoint.authType=settings.value("JustConnect/AuthType").toString();
    p.endpoint.loginDomain=settings.value("JustConnect/LoginDomain").toString();
    const auto country=settings.value("JustConnect/PhoneCountryCode").toString(), phone=settings.value("JustConnect/PhoneNumber").toString();
    if (!country.isEmpty() && !phone.isEmpty()) p.endpoint.phone=country+'-'+phone;
    if (!settings.value("Common/NeedsConfiguration",false).toBool()) p.endpoint.server=settings.value("JustConnect/ServerAddress").toString();
    p.endpoint.port=settings.value("JustConnect/ServerPort").toInt();
    p.dns.secondary=settings.value("JustConnect/SecondaryDNS").toString();
    p.dns.localDnsServer=settings.value("JustConnect/LocalDNSServer").toString();
    p.dns.ttl=settings.value("JustConnect/DNSTTL",3600).toInt();
    p.dns.disableRemoteDns=settings.value("JustConnect/DisableRemoteDNS").toBool();
    const auto bind=[](int port) { return port ? "127.0.0.1:"+QString::number(port) : QString(); };
    p.proxy.socksBind=bind(settings.value("JustConnect/SOCKS5Port").toInt());
    p.proxy.httpBind=bind(settings.value("JustConnect/HTTPPort").toInt());
    p.behavior.bindInterface=settings.value("JustConnect/BindInterface").toString();
    p.behavior.autoDetectInterface=settings.value("JustConnect/AutoDetectInterface").toBool();
    return p;
}
