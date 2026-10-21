#include "application/profileservice.h"
#include <QCoreApplication>
#include <QSettings>
#include <QTemporaryDir>
#include <cstdlib>
#include <iostream>
static void check(bool ok,const char *message) { if (!ok) { std::cerr<<message<<'\n'; std::exit(1); } }
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    QTemporaryDir folder;
    check(folder.isValid(),"isolated profile");
    const auto path=folder.filePath("profile.ini");
    {
        QSettings settings(path,QSettings::IniFormat);
        settings.setValue("Credential/Username","saved-user");
        settings.setValue("Credential/Password",QString::fromLatin1(QByteArray("saved-password").toBase64()));
        settings.setValue("Credential/TOTPSecret","saved-totp");
        settings.setValue("JustConnect/ServerAddress","vpn.example.edu");
        settings.setValue("JustConnect/ServerPort",8443);
        settings.setValue("JustConnect/TLSVerify",false); settings.setValue("JustConnect/TLSCAPEM","stored CA");
        settings.setValue("JustConnect/AuthType","smsCheckCode");
        settings.setValue("JustConnect/AuthID","returned-id"); settings.setValue("JustConnect/AuthSubType","sms");
        settings.setValue("JustConnect/LoginDomain","selected-domain");
        settings.setValue("JustConnect/PhoneCountryCode","86");
        settings.setValue("JustConnect/PhoneNumber","123456");
        settings.setValue("JustConnect/SOCKS5Port",0); settings.setValue("JustConnect/HTTPPort",11081);
        settings.setValue("JustConnect/OutsideAccess",true);
        settings.setValue("JustConnect/ExtraArguments","-password obsolete-argument");
        settings.setValue("JustConnect/SecondaryDNS","10.0.0.2");
        settings.setValue("JustConnect/LocalDNSServer","127.0.0.1:5353");
        settings.setValue("JustConnect/DNSTTL",60);
        settings.setValue("JustConnect/DisableRemoteDNS",true);
        settings.setValue("JustConnect/BindInterface","fixture0");
        settings.setValue("JustConnect/AutoDetectInterface",true);
        settings.sync(); check(settings.status()==QSettings::NoError,"persist profile fixture");
    }
    QSettings saved(path,QSettings::IniFormat);
    const auto profile=ProfileService::load(saved);
    check(profile.credentials.username=="saved-user" && profile.credentials.password.isEmpty() && profile.credentials.totpSecret.isEmpty(),"public profile loading never reads legacy secrets");
    check(profile.endpoint.server=="vpn.example.edu" && profile.endpoint.port==8443 && profile.endpoint.authType=="smsCheckCode" && profile.endpoint.authId=="returned-id" && profile.endpoint.authSubType=="sms" && profile.endpoint.loginDomain=="selected-domain" && profile.endpoint.phone=="86-123456","selected endpoint and authentication survive reload");
    check(!profile.tls.verify && profile.tls.caPem=="stored CA","explicit session TLS policy survives disk reload");
    saved.remove("JustConnect/TLSVerify"); saved.remove("JustConnect/TLSCAPEM");
    check(ProfileService::load(saved).tls.verify,"legacy profiles default to certificate validation");
    check(profile.proxy.socksBind.isEmpty() && profile.proxy.httpBind=="127.0.0.1:11081","zero disables listener; legacy outside-access option never exposes it");
    check(profile.dns.secondary=="10.0.0.2" && profile.dns.localDnsServer=="127.0.0.1:5353" && profile.dns.ttl==60 && profile.dns.disableRemoteDns && profile.behavior.bindInterface=="fixture0" && profile.behavior.autoDetectInterface,"supported network settings survive reload");
    saved.setValue("Common/NeedsConfiguration",true);
    check(ProfileService::load(saved).endpoint.server.isEmpty(),"legacy protocol cannot connect before explicit configuration");
    check(saved.value("JustConnect/ServerAddress")=="vpn.example.edu","legacy endpoint is retained for manual recovery");
    std::cout<<"PASS: profile reload, credentials, listener boundaries and legacy confirmation\n";
}
