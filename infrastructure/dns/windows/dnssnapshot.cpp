#include "infrastructure/dns/windows/dnssnapshot.h"
#include "infrastructure/dns/windows/dnscontract.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QDir>

namespace {
bool strings(const QJsonValue &value)
{
    if (!value.isArray()) return false;
    for (const auto &item : value.toArray()) if (!item.isString()) return false;
    return true;
}

bool valid(const QJsonObject &data)
{
    for (const auto &key : {"interfaces", "clients", "nrpt", "doh"})
        if (!data[key].isArray()) return false;
    if (!data["global"].isObject() || !strings(data["global"].toObject()["SuffixSearchList"])
        || !data["doh_supported"].isBool()) return false;
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
        const QStringList stages{"native", "local_session", "nrpt_sources", "nrpt", "nrpt_rows", "nrpt_consistency", "doh_class", "serialize",
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
