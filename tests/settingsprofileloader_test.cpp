#include "infrastructure/settings/settingsprofileloader.h"
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
        settings.setValue("JustConnect/AuthType","smsCheckCode");
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
    const auto profile=SettingsProfileLoader::load(saved);
    check(profile.credentials.username=="saved-user" && profile.credentials.password=="saved-password" && profile.credentials.totpSecret=="saved-totp","stored credential decoding");
    check(profile.endpoint.server=="vpn.example.edu" && profile.endpoint.port==8443 && profile.endpoint.authType=="smsCheckCode" && profile.endpoint.loginDomain=="selected-domain" && profile.endpoint.phone=="86-123456","selected endpoint and authentication survive reload");
    check(profile.proxy.socksBind.isEmpty() && profile.proxy.httpBind=="127.0.0.1:11081","zero disables listener; legacy outside-access option never exposes it");
    check(profile.dns.secondary=="10.0.0.2" && profile.dns.localDnsServer=="127.0.0.1:5353" && profile.dns.ttl==60 && profile.dns.disableRemoteDns && profile.behavior.bindInterface=="fixture0" && profile.behavior.autoDetectInterface,"supported network settings survive reload");
    const auto interactive=SettingsProfileLoader::load(saved,"interactive-user","interactive-password");
    check(interactive.credentials.username=="interactive-user" && interactive.credentials.password=="interactive-password","interactive credentials override persisted values");
    saved.setValue("Common/NeedsConfiguration",true);
    check(SettingsProfileLoader::load(saved).endpoint.server.isEmpty(),"legacy protocol cannot connect before explicit configuration");
    check(saved.value("JustConnect/ServerAddress")=="vpn.example.edu","legacy endpoint is retained for manual recovery");
    std::cout<<"PASS: profile reload, credentials, listener boundaries and legacy confirmation\n";
}
