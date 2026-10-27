#include "infrastructure/dns/windows/dnssnapshot.h"
#include "infrastructure/dns/windows/dnscontract.h"
#include "infrastructure/dns/domainlimits.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QDir>
#include <QHostAddress>
#include <QUuid>
#include <limits>

namespace {
bool strings(const QJsonValue &value)
{
    if (!value.isArray()) return false;
    for (const auto &item : value.toArray()) if (!item.isString()) return false;
    return true;
}
bool unsignedNumber(const QJsonValue &value, qint64 maximum=std::numeric_limits<quint32>::max())
{
    const auto number=value.toInteger(-1);
    return value.isDouble() && number>=0 && number<=maximum;
}
bool flags(const QJsonValue &value)
{
    if(!value.isString())return false;
    bool ok=false;
    const auto text=value.toString();
    const auto number=text.toULongLong(&ok);
    return ok && text==QString::number(number);
}
bool nullableText(const QJsonValue &value)
{
    return value.isNull() || value.isString();
}
bool properties(const QJsonValue &value)
{
    if(!value.isArray() || value.toArray().size()>qsizetype(NetworkDnsDomainLimit))return false;
    for(const auto &item:value.toArray()){
        const auto row=item.toObject();
        if(!item.isObject() || !unsignedNumber(row["Version"]) || !unsignedNumber(row["ServerIndex"])
            || !unsignedNumber(row["Type"]))return false;
        const auto type=row["Type"].toInteger();
        if(row["Version"].toInteger()!=WindowsDNS::PropertyVersion || (type!=WindowsDNS::DohProperty && type!=WindowsDNS::DotProperty)){
            if(!row["Settings"].isNull())return false;
            continue;
        }
        const auto settings=row["Settings"].toObject();
        if(!row["Settings"].isObject() || !flags(settings["Flags"]))return false;
        if(type==WindowsDNS::DohProperty){if(!nullableText(settings["Template"]))return false;}
        else if(!nullableText(settings["Hostname"]) || !unsignedNumber(settings["Port"],65535))return false;
    }
    return true;
}
bool nativeSettings(const QJsonValue &value,bool adapter)
{
    const auto row=value.toObject();
    if(!value.isObject() || !unsignedNumber(row["Status"]))return false;
    const auto status=row["Status"].toInteger();
    if(status)return WindowsDNS::settingsUnavailable(static_cast<unsigned long>(status)) && row["Value"].isNull();
    const auto settings=row["Value"].toObject();
    if(!row["Value"].isObject() || !flags(settings["Flags"]) || !nullableText(settings["Domain"])
        || !nullableText(settings["SearchList"]))return false;
    if(!adapter)return flags(settings["SettingFlags"]);
    return nullableText(settings["NameServer"]) && nullableText(settings["ProfileNameServer"])
        && nullableText(settings["SupplementalSearchList"]) && unsignedNumber(settings["DisableUnconstrainedQueries"])
        && unsignedNumber(settings["EncryptedDnsAdapterFlags"])
        && properties(settings["ServerProperties"]) && properties(settings["ProfileServerProperties"]);
}

bool valid(const QJsonObject &data)
{
    for (const auto &key : {"interfaces", "clients", "nrpt", "doh", "adapters"})
        if (!data[key].isArray()) return false;
    if (!data["global"].isObject() || !strings(data["global"].toObject()["SuffixSearchList"])
        || !data["doh_supported"].isBool() || !nativeSettings(data["native_global"],false)) return false;
    if(data["adapters"].toArray().size()>qsizetype(NetworkDnsDomainLimit))return false;
    for(const auto &value:data["adapters"].toArray()){
        const auto row=value.toObject();
        if(!value.isObject() || !unsignedNumber(row["InterfaceIndex"]) || !unsignedNumber(row["Ipv6IfIndex"])
            || (!row["InterfaceIndex"].toInteger() && !row["Ipv6IfIndex"].toInteger())
            || !row["Guid"].isString() || QUuid(row["Guid"].toString()).isNull() || !flags(row["Luid"])
            || row["Luid"]=="0" || !unsignedNumber(row["IfType"]) || !unsignedNumber(row["OperStatus"])
            || !unsignedNumber(row["Ipv4Metric"]) || !unsignedNumber(row["Ipv6Metric"])
            || !nullableText(row["DnsSuffix"]) || !nativeSettings(row["Settings"],true)
            || !row["DnsServers"].isArray() || row["DnsServers"].toArray().size()>qsizetype(NetworkDnsDomainLimit))return false;
        for(const auto &server:row["DnsServers"].toArray()){
            const auto endpoint=server.toObject();
            if(!server.isObject() || !endpoint["Address"].isString() || QHostAddress(endpoint["Address"].toString()).isNull()
                || !unsignedNumber(endpoint["Port"],65535) || !endpoint["Port"].toInteger())return false;
        }
    }
    for (const auto &value : data["interfaces"].toArray()) {
        const auto row = value.toObject();
        const auto index = row["InterfaceIndex"].toInteger(-1);
        const auto family = row["AddressFamily"].toInteger(-1);
        if (!value.isObject() || index <= 0 || (family != 2 && family != 23)
            || !strings(row["ServerAddresses"])) return false;
    }
    for (const auto &value : data["clients"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || row["InterfaceIndex"].toInteger(-1) <= 0
            || !row["ConnectionSpecificSuffix"].isString() || !strings(row["ConnectionSpecificSuffixSearchList"])) return false;
    }
    for (const auto &value : data["nrpt"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || !strings(row["Namespace"]) || row["Namespace"].toArray().isEmpty()
            || !strings(row["NameServers"]) || !strings(row["DirectAccessDnsServers"])
            || !row["DirectAccessEnabled"].isBool() || !row["QueryPolicy"].isString()
            || !row["SecureNameQueryFallback"].isString()) return false;
    }
    for (const auto &value : data["doh"].toArray()) {
        const auto row = value.toObject();
        if (!value.isObject() || !row["ServerAddress"].isString() || !row["DohTemplate"].isString()
            || !row["AllowFallbackToUdp"].isBool() || !row["AutoUpgrade"].isBool()) return false;
    }
    return true;
}
}

DnsSnapshot readWindowsDnsSnapshot(const PlatformCommandRunner &runner)
{
    using Status = PlatformOperationResult::Status;
    QString program;
#ifdef Q_OS_WIN
    program = QDir(QCoreApplication::applicationDirPath()).filePath("JustConnectDnsReader.exe");
#else
    if (!runner) return {{Status::Unsupported, "Windows DNS snapshot unavailable on this platform"}, {}};
#endif
    const QStringList arguments;
    const auto command = runner ? runner(program, arguments) : runPlatformCommand(program, arguments, WindowsDNS::SnapshotTimeoutMs);
    if (!command.result.succeeded()) {
        auto result = command.result;
        const QRegularExpression phase(QStringLiteral("^JCDNS phase=([A-Za-z0-9_]{1,64}) elapsed_ms=([0-9]{1,8})$"));
        const QStringList stages{"native", "local_session", "nrpt_sources", "nrpt", "nrpt_rows", "nrpt_consistency", "doh_class", "adapter_dns", "global_dns", "serialize",
            "MSFT_DNSClientDohServerAddress", "MSFT_DNSClientServerAddress", "MSFT_DNSClient", "MSFT_DNSClientGlobalSetting"};
        QString last;
        for (const auto &line : command.standardError.split('\n')) {
            const auto match = phase.match(line.trimmed());
            if (match.hasMatch() && stages.contains(match.captured(1)))
                last = QStringLiteral(" (DNS phase %1 at %2 ms)").arg(match.captured(1), match.captured(2));
        }
        result.detail += last;
        return {result, {}};
    }
    const auto bytes = command.output.toUtf8();
    if (bytes.size() > qsizetype(WindowsDNS::SnapshotBytes)) return {{Status::Failed, "System resolver snapshot too large"}, {}};
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject() || !valid(document.object()))
        return {{Status::Failed, "Invalid system resolver snapshot"}, {}};
    return {{}, document.object()};
}
