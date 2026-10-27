#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/dns/dnsdomains.h"
#include <QDeadlineTimer>
#include <QDebug>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QThread>
#include <limits>

bool macDnsServersBelongTo(const QJsonArray &effective,const QJsonArray &configured)
{
    if(effective.isEmpty())return false;
    for(const auto &value:effective)if(!value.isString() || !configured.contains(value))return false;
    return true;
}

bool validMacOriginalDnsContext(const QJsonObject &context)
{
    const auto index=context["interface_index"].toInteger(-1),port=context["port"].toInteger(-1);
    const auto interface=context["interface"].toString();
    if(context.size()!=7 || index<0 || index>std::numeric_limits<quint32>::max() || context["interface_index"]!=QJsonValue(index)
        || port<1 || port>65535 || context["port"]!=QJsonValue(port) || interface.isEmpty() || interface.size()>63
        || interface.contains(QChar::Null) || interface.contains('\n') || interface.contains('\r')
        || !context["addresses"].isArray() || context["addresses"].toArray().isEmpty() || context["addresses"].toArray().size()>qsizetype(NetworkDnsDomainLimit)
        || !context["servers"].isArray() || context["servers"].toArray().isEmpty() || context["servers"].toArray().size()>qsizetype(NetworkDnsDomainLimit)
        || !context["domains"].isArray() || context["domains"].toArray().isEmpty() || context["domains"].toArray().size()>qsizetype(NetworkDnsDomainLimit)
        || (!context["state"].isNull() && !context["state"].isObject()))return false;
    for(const auto &server:context["servers"].toArray()){
        const auto value=server.toString();
        if(!server.isString() || value.isEmpty() || value.size()>253 || value.contains(QChar::Null) || value.contains('\n') || value.contains('\r'))return false;
    }
    for(const auto &address:context["addresses"].toArray()){
        const auto value=address.toString();if(!address.isString() || value.isEmpty() || value.size()>253 || value.contains(QChar::Null) || value.contains('\n') || value.contains('\r'))return false;
    }
    QSet<QString> seen;
    for(const auto &domain:context["domains"].toArray()){
        const auto value=domain.toString();
        if(!domain.isString() || (!value.isEmpty() && !canonicalDnsDomain(value)) || seen.contains(value))return false;
        seen.insert(value);
    }
    return true;
}

std::optional<QJsonObject> originalMacDnsResolver(QJsonObject resolver,const QJsonObject &context)
{
    if(!validMacOriginalDnsContext(context))return {};
    resolver["servers"]=context["servers"];resolver["port"]=context["port"];
    if(resolver["scope"]=="unscoped"){
        resolver["interface_index"]=context["interface_index"];
        if(context["interface_index"].toInteger()>0)resolver["interface_name"]=context["interface"];
        else resolver.remove("interface_name");
    }
    return resolver;
}

std::optional<QJsonArray> parseMacDnsResolvers(const QString &configuration)
{
    if (configuration.toUtf8().size() > MacDnsSnapshotBytes || configuration.contains(QChar::Null)) return {};
    if (configuration.trimmed() == "No DNS configuration available") return QJsonArray{};
    const QRegularExpression header(QStringLiteral("^resolver #([0-9]+)$"));
    const QRegularExpression indexed(QStringLiteral("^(nameserver|search domain)\\[([0-9]+)\\]$"));
    const QRegularExpression interface(QStringLiteral("^([0-9]+)(?: \\(([^()]*)\\))?$"));
    QJsonArray result;
    QJsonObject row, properties;
    QSet<QString> fields;
    QString scope = "unscoped";
    bool section = false;
    const auto finish = [&] {
        if (!row.isEmpty()) {
            if (!properties.isEmpty()) row["properties"] = properties;
            result.append(row);
        }
        row = {}; properties = {}; fields.clear();
    };
    for (const auto &raw : configuration.split('\n')) {
        const auto line = raw.trimmed();
        if (line.isEmpty()) continue;
        if (line.startsWith("DNS configuration")) {
            finish(); section = true;
            if (line == "DNS configuration") scope = "unscoped";
            else if (line == "DNS configuration (for scoped queries)") scope = "interface";
            else if (line == "DNS configuration (for service-specific queries)") scope = "service";
            else return {};
            continue;
        }
        const auto match = header.match(line);
        if (match.hasMatch()) {
            finish();
            bool valid = false; const auto id = match.captured(1).toUInt(&valid);
            if (!valid || !id || result.size() >= qsizetype(NetworkDnsDomainLimit)) return {};
            row = {{"scope",scope},{"resolver",qint64(id)},{"servers",QJsonArray{}},{"search",QJsonArray{}},
                {"flags",QJsonArray{}},{"interface_index",0}};
            continue;
        }
        const auto colon = line.indexOf(':');
        if (row.isEmpty() || colon <= 0) return {};
        const auto key = line.first(colon).trimmed(), value = line.mid(colon+1).trimmed();
        if (fields.contains(key) || fields.size() >= qsizetype(NetworkDnsDomainLimit)) return {};
        fields.insert(key);
        const auto index = indexed.match(key);
        if (index.hasMatch()) {
            const auto field = index.captured(1) == "nameserver" ? "servers" : "search";
            auto values = row[field].toArray(); bool valid = false;
            const auto number = index.captured(2).toUInt(&valid);
            if (!valid || number != quint64(values.size()) || values.size() >= qsizetype(NetworkDnsDomainLimit) || value.isEmpty()) return {};
            values.append(value); row[field] = values;
        } else if (key.startsWith("nameserver[") || key.startsWith("search domain[")) return {};
        else if (key == "domain" || key == "options") row[key] = value;
        else if (key == "port" || key == "order" || key == "timeout") {
            bool valid = false; const auto number = value.toUInt(&valid);
            if (!valid || (key == "port" && (!number || number > 65535))) return {};
            row[key] = qint64(number);
        } else if (key == "if_index") {
            const auto parsed = interface.match(value); bool valid = false;
            const auto number = parsed.captured(1).toUInt(&valid);
            if (!parsed.hasMatch() || !valid) return {};
            row["interface_index"] = qint64(number);
            if (!parsed.captured(2).isEmpty()) row["interface_name"] = parsed.captured(2);
        } else if (key == "flags") {
            QJsonArray flags;
            for (const auto &flag : value.split(',',Qt::SkipEmptyParts)) flags.append(flag.trimmed());
            row["flags"] = flags;
        } else if (key != "reach") properties[key] = value; // Reachability is live state, not resolver configuration.
    }
    finish();
    if (!section && result.isEmpty()) return {};
    return result;
}

bool macDnsResolverUsesPeer(const QJsonObject &row,const QString &peer,quint32 interfaceIndex)
{
    const auto flags = row["flags"].toArray();
    if (peer.isEmpty() || row["servers"].toArray() != QJsonArray{peer}
        || row["port"].toInteger(DnsServerPort) != DnsServerPort || !row["options"].toString().isEmpty()) return false;
    if (interfaceIndex) return row["scope"] == "interface" && row["interface_index"].toInteger() == interfaceIndex && flags.contains("Scoped");
    return row["scope"] == "unscoped" && flags.contains("Supplemental") && !flags.contains("Scoped") && !row["interface_index"].toInteger();
}

bool macDnsResolverMatches(const QString &configuration,const QString &peer,const QStringList &domains)
{
    if (peer.isEmpty() || domains.isEmpty()) return false;
    const auto resolvers = parseMacDnsResolvers(configuration);
    if (!resolvers) return false;
    const QSet<QString> wanted(domains.begin(),domains.end());
    QSet<QString> ready;
    for (const auto &value : *resolvers) {
        const auto row = value.toObject(); const auto flags = row["flags"].toArray();
        const auto domain = row["domain"].toString();
        if (row["scope"] != "unscoped" || !flags.contains("Supplemental") || !wanted.contains(domain)) continue;
        if (!macDnsResolverUsesPeer(row,peer)) return false;
        ready.insert(domain);
    }
    return ready == wanted;
}

PlatformOperationResult waitForMacDnsResolver(const QString &peer,const QStringList &domains,PlatformCommandRunner run)
{
    using Status = PlatformOperationResult::Status;
    constexpr int ActivationTimeoutMs = 5000,PublicationPollMs = 50;
    QDeadlineTimer deadline(ActivationTimeoutMs);
    QString lastConfiguration;
    if (!run) run = [&deadline](const QString &program,const QStringList &arguments) {
        return runPlatformCommand(program,arguments,int(deadline.remainingTime()));
    };
    while (!deadline.hasExpired()) {
        const auto current = run(QStringLiteral("/usr/sbin/scutil"),{QStringLiteral("--dns")});
        if (!current.result.succeeded()) return current.result;
        if (macDnsResolverMatches(current.output,peer,domains)) return {};
        lastConfiguration = current.output;
        QThread::msleep(PublicationPollMs);
    }
    qWarning().noquote() << "DNS activation timeout; expected" << peer << domains << '\n' << lastConfiguration;
    return {Status::TimedOut,QStringLiteral("Owned supplemental DNS resolver did not become effective.")};
}
