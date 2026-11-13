#include "application/defaultsettings.h"

#include <QSettings>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTemporaryDir>
#include <QVariant>

#include "application/applicationconstants.h"
#include "application/connectioncredentialvault.h"
#include "core/connectionoptions.h"

namespace {
constexpr int PreviousConfigVersion = 9;

const QVariantMap &defaults()
{
    static const QVariantMap values{
        {"Credential/Username", ""},
        {DefaultSettings::RememberAuthentication, DefaultSettings::RememberAuthenticationByDefault},

        {"Common/ConnectAfterStart", false},
        {"Common/CheckUpdateAfterStart", false},
        {"Common/ReconnectTime", 1},
        {"Common/AutoReconnect", false},

        {"Common/NeedsConfiguration", false},
        {"JustConnect/ConnectionKind", "Custom"},
        {"JustConnect/ServerAddress", ""},
        {"JustConnect/ServerPort", 443},
        {"JustConnect/TLSVerify", TlsOptions{}.verify},
        {"JustConnect/TLSCAPEM", ""},
        {"JustConnect/AllowUnverifiedNodes", TlsOptions{}.allowUnverifiedNodes},
        {"JustConnect/SecondaryDNS", ""},
        {DefaultSettings::RoutingModeKey, DefaultSettings::AutomaticMode},
        {"JustConnect/LocalDNSServer", ""},
        {"JustConnect/DNSTTL", DnsOptions{}.ttl},
        {DefaultSettings::SocksPortKey, DefaultSettings::DefaultSocksPort},
        {"JustConnect/HTTPPort", 11081},
        {"JustConnect/KeepAliveMode", KeepAliveOptions{}.mode},
        {"JustConnect/KeepAliveURL", ""},

        {"JustConnect/LoginDomain", ""},
        {"JustConnect/AuthType", "psw"},
        {"JustConnect/AuthID", ""},
        {"JustConnect/AuthSubType", ""},
        {DefaultSettings::SignInMethodName, ""},
        {"JustConnect/PhoneCountryCode", "86"},
        {"JustConnect/PhoneNumber", ""},

        {"JustConnect/BindInterface", ""},
        {"JustConnect/DisableRemoteDNS", DnsOptions{}.disableRemoteDns},

        {"JustConnect/AutoDetectInterface", ConnectionBehavior{}.autoDetectInterface},

    };
    return values;
}
void apply(QSettings &settings, bool overwrite)
{
    for (auto it=defaults().cbegin();it!=defaults().cend();++it)
        if (overwrite || !settings.contains(it.key())) settings.setValue(it.key(),it.value());
    if (overwrite) {
        settings.remove(DefaultSettings::DomainDnsRules);
        settings.setValue("Common/ConfigVersion", ApplicationConstants::ConfigVersion);
    }
}
}

void DefaultSettings::reset(QSettings &settings) { apply(settings, true); }
void DefaultSettings::initialize(QSettings &settings) { apply(settings, false); }

bool DefaultSettings::isUnconfiguredDefault(const QSettings &settings)
{
    const int version = settings.value("Common/ConfigVersion", ApplicationConstants::ConfigVersion).toInt();
    if (version != ApplicationConstants::ConfigVersion && version != PreviousConfigVersion)
        return false;
    for (const auto &key : settings.allKeys()) {
        const auto value = settings.value(key).toString();
        if (key == "Common/ConfigVersion" || key == ConnectionCredentialVault::ScopeSetting || key == "JustConnect/CampusTargets")
            continue;
        // Earlier builds wrote these fields before a server was ever chosen.
        if ((key == "JustConnect/ProfileKind" && value == "Custom")
            || (key == "JustConnect/AuthType" && value.isEmpty())
            || (key == RememberAuthentication && value == "false")
            || (key == DomainDnsRules && value.isEmpty()))
            continue;
        if (!defaults().contains(key) || value != defaults().value(key).toString())
            return false;
    }
    return true;
}

void DefaultSettings::applyBuiltInConnection(QSettings &settings)
{
    const auto &connection = builtInConnection();
    for (auto it = connection.cbegin(); it != connection.cend(); ++it)
        settings.setValue(it.key(), it.value());
}

bool DefaultSettings::isPublicKey(const QString &key)
{
    return key=="Common/ConfigVersion" || key==DomainDnsRules || defaults().contains(key);
}

const QVariantMap &DefaultSettings::builtInConnection()
{
    static const auto values=[] {
        const QSettings input(QStringLiteral(JC_BUNDLED_CONNECTION),QSettings::IniFormat);
        auto values=publicValues(input);
        if (input.status()!=QSettings::NoError || values.isEmpty()) qFatal("Cannot read the bundled connection.");
        return values;
    }();
    return values;
}

bool DefaultSettings::matchesBuiltInServer(const QString &server)
{
    const auto bundledServer=builtInConnection().value("JustConnect/ServerAddress").toString();
    return server.trimmed().compare(bundledServer,Qt::CaseInsensitive)==0;
}

bool DefaultSettings::isBuiltInConnection(const QSettings &settings)
{
    const auto &connection = builtInConnection();
    return !settings.value("Common/NeedsConfiguration").toBool()
        && settings.value("JustConnect/ConnectionKind") == connection.value("JustConnect/ConnectionKind")
        && settings.value("JustConnect/ServerAddress") == connection.value("JustConnect/ServerAddress")
        && settings.value("JustConnect/ServerPort").toInt() == connection.value("JustConnect/ServerPort").toInt();
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
