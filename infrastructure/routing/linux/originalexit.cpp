#include "infrastructure/routing/linux/originalexit.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QJsonDocument>
#include <QSet>

std::optional<QStringList> linuxRouteEndpoints(const QStringList &prefixes)
{
    if (prefixes.size() > LinuxRouteSnapshotRows) return {};
    QSet<QString> unique;
    QStringList result;
    for (const auto &prefix : prefixes) {
        if (!canonicalIpv4Prefix(prefix)) return {};
        in_addr address{};
        const auto parts = prefix.split('/');
        ::inet_pton(AF_INET, parts[0].toLatin1().constData(), &address);
        const quint64 first = ntohl(address.s_addr), last = first + (quint64(1) << (32 - parts[1].toInt())) - 1;
        for (const auto number : {first, last}) {
            address.s_addr = htonl(quint32(number));
            char text[INET_ADDRSTRLEN]{};
            if (!::inet_ntop(AF_INET, &address, text, sizeof(text))) return {};
            const auto endpoint = QString::fromLatin1(text);
            if (!unique.contains(endpoint)) { unique.insert(endpoint); result.append(endpoint); }
        }
    }
    return result;
}

PlatformOperationResult verifyLinuxOriginalExit(const QString &interface, const QString &source, const QString &gateway,
    const QStringList &prefixes, const PlatformCommandRunner &reader)
{
    using Status = PlatformOperationResult::Status;
    if (!canonicalLinuxInterfaceName(interface) || !canonicalUnicastIpv4(source)
        || (!gateway.isEmpty() && !canonicalUnicastIpv4(gateway)) || source == gateway
        || prefixes.size() > LinuxRouteSnapshotRows)
        return {Status::Failed,"Invalid original route verification input."};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    const auto queries = linuxRouteEndpoints(prefixes);
    if (!queries) return {Status::Failed,"Invalid capture prefixes."};
    if (queries->isEmpty()) return {};
    QByteArray batch;
    for (const auto &address : *queries)
        batch += "route get " + address.toLatin1() + " from " + source.toLatin1() + '\n';
    const QStringList args{"-N","-j","-4","-batch","-"};
    const auto read = reader ? reader(utility,args) : runPlatformCommand(utility,args,LinuxRouteOperationTimeoutMs,batch);
    if (!read.result.succeeded()) return read.result;
    if (read.output.toUtf8().size() > LinuxRouteSnapshotBytes || read.output.contains(QChar::ReplacementCharacter))
        return {Status::Failed,"Original exit verification exceeded its complete output budget."};
    const auto lines = read.output.split('\n',Qt::SkipEmptyParts);
    if (lines.size() != queries->size()) return {Status::Failed,"Incomplete original exit verification."};
    for (qsizetype i=0; i<lines.size(); ++i) {
        const auto parsed = QJsonDocument::fromJson(lines[i].toUtf8());
        const auto rows = parsed.array();
        if (!parsed.isArray() || rows.size() != 1 || !rows[0].isObject()) return {Status::Failed,"Invalid original exit verification."};
        const auto row = rows[0].toObject();
        if (row["dst"] != (*queries)[i] || row["from"] != source || row["dev"] != interface
            || row["gateway"].toString() != gateway || row.contains("nhid") || row.contains("nexthops")
            || (row.contains("type") && row["type"] != "unicast") || !row["flags"].isArray() || !row["flags"].toArray().isEmpty())
            return {Status::Unsupported,"Changed capture targets no longer share the confirmed original exit."};
    }
    return {};
}
