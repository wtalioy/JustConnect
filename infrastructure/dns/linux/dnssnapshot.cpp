#include "infrastructure/dns/linux/dnssnapshot.h"
#include "infrastructure/process/command.h"
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>
#include <optional>

namespace {
constexpr int MaxSearchDomains = 64, MaxTokenBytes = 255, MaxLinks = 64;

struct ResolvConf { QStringList nameservers, search; QString domain; };

std::optional<ResolvConf> parseResolvConf(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return std::nullopt;
    ResolvConf parsed;
    for (auto line : QString::fromUtf8(file.readAll()).split('\n')) {
        int cut = line.indexOf('#');
        const int semicolon = line.indexOf(';');
        if (semicolon >= 0 && (cut < 0 || semicolon < cut)) cut = semicolon;
        if (cut >= 0) line.truncate(cut);
        const auto tokens = line.simplified().split(' ', Qt::SkipEmptyParts);
        if (tokens.isEmpty()) continue;
        auto append = [](QStringList &values, const QString &value) {
            if (values.contains(value)) return true;
            if (values.size() >= MaxSearchDomains || value.size() > MaxTokenBytes || value.contains(QChar(0))) return false;
            values.append(value);
            return true;
        };
        if (tokens.first() == QStringLiteral("nameserver")) {
            for (int i = 1; i < tokens.size(); ++i)
                if (!append(parsed.nameservers, tokens[i])) return std::nullopt;
        } else if (tokens.first() == QStringLiteral("search")) {
            for (int i = 1; i < tokens.size(); ++i)
                if (!append(parsed.search, tokens[i])) return std::nullopt;
        } else if (tokens.first() == QStringLiteral("domain") && tokens.size() >= 2) {
            parsed.domain = tokens[1];
        }
    }
    return parsed;
}

// "Link 2 (enp3s0)" opens one per-link section of `resolvectl status`.
const QRegularExpression LinkHeader{QStringLiteral("^Link (\\d+) \\(([^)]+)\\)\\s*$")};

// Label lines carry only letters and spaces before the colon, so IPv6 values
// ("240e:58::6666") never read as labels. systemd right-aligns labels inside
// their section, so a label may be indented ("       DNS Servers:") while the
// section's longest one is flush left ("Current DNS Server:").
const QRegularExpression LabelLine{QStringLiteral("^\\s*([A-Za-z][A-Za-z ]*):\\s*(.*)$")};

// Per-link DNS state from an active systemd-resolved: the global resolv.conf
// files cannot describe per-link servers or routing domains, and the
// original-network view must describe both. Parsed from `resolvectl status`
// (LC_ALL=C pinned by the command runner); best effort — a host without an
// active resolved keeps the resolv_conf-only snapshot.
std::optional<QJsonObject> readResolvedPerLink(const QString &program)
{
    const auto command = runPlatformCommand(program, {QStringLiteral("status")}, 2000, QProcessEnvironment{});
    if (!command.result.succeeded()) return std::nullopt;
    return parseResolvedPerLinkStatus(command.output);
}
}

// Parses the per-link sections of `resolvectl status` output. Exported for the
// regression test: right-aligned labels and wrapped value rows only appear on
// a live desktop, which CI does not have.
std::optional<QJsonObject> parseResolvedPerLinkStatus(const QString &status)
{
    QJsonArray links;
    int index = -1;
    QString interface;
    QJsonArray servers, domains;
    QString continuation;
    bool overflow = false, defaultRoute = false, valid = true;
    const auto appendToken = [](QJsonArray &list, const QString &token, bool *overflow) {
        if (list.contains(token)) return;
        if (list.size() >= MaxSearchDomains || token.size() > MaxTokenBytes || token.contains(QChar(0))) {
            *overflow = true; return;
        }
        list.append(token);
    };
    const auto flush = [&]() {
        if (index >= 0 && (overflow || !servers.isEmpty() || !domains.isEmpty())) {
            if (overflow || links.size() >= MaxLinks) valid = false;
            else links.append(QJsonObject{{"index", index}, {"interface", interface},
                {"servers", servers}, {"domains", domains}, {"default_route", index == 0 || defaultRoute}});
        }
        index = -1;
        interface.clear();
        servers = QJsonArray();
        domains = QJsonArray();
        continuation.clear();
        overflow = false;
        defaultRoute = false;
    };
    const auto accept = [&](const QString &key, const QString &value) {
        if (key == QStringLiteral("DNS Servers")) {
            continuation = QStringLiteral("servers");
            for (const auto &token : value.simplified().split(' ', Qt::SkipEmptyParts))
                appendToken(servers, token, &overflow);
        } else if (key == QStringLiteral("DNS Domain")) {
            continuation = QStringLiteral("domains");
            for (const auto &token : value.simplified().split(' ', Qt::SkipEmptyParts))
                appendToken(domains, token, &overflow);
        } else {
            continuation.clear();
            if (key == QStringLiteral("Protocols"))
                defaultRoute = value.split(' ', Qt::SkipEmptyParts).contains(QStringLiteral("+DefaultRoute"));
            else if (key == QStringLiteral("Default Route")) defaultRoute = value == QStringLiteral("yes");
        }
    };
    for (auto line : status.split('\n')) {
        if (line == QStringLiteral("Global")) {
            flush();
            index = 0;
            continue;
        }
        const auto header = LinkHeader.match(line);
        if (header.hasMatch()) {
            flush();
            index = header.captured(1).toInt();
            interface = header.captured(2);
            continue;
        }
        const auto label = LabelLine.match(line);
        if (label.hasMatch()) {
            accept(label.captured(1).trimmed(), label.captured(2));
            continue;
        }
        if (line.startsWith(QChar(' ')) || line.startsWith(QChar('\t'))) {
            // A wrapped value row of the label above it.
            const auto tokens = line.simplified().split(' ', Qt::SkipEmptyParts);
            if (continuation == QStringLiteral("servers"))
                for (const auto &token : tokens) appendToken(servers, token, &overflow);
            else if (continuation == QStringLiteral("domains"))
                for (const auto &token : tokens) appendToken(domains, token, &overflow);
            continue;
        }
        continuation.clear();
    }
    flush();
    if (!valid) return std::nullopt;
    return QJsonObject{{"links", links}};
}

DnsSnapshot readLinuxDnsSnapshot()
{
    using Status = PlatformOperationResult::Status;
    const auto configuration = parseResolvConf(QStringLiteral("/etc/resolv.conf"));
    if (!configuration) return {{Status::Failed, "Cannot read /etc/resolv.conf"}, {}};
    auto nameservers = configuration->nameservers;
    // The systemd-resolved stub listener forwards to real upstreams; snapshot those instead.
    if (nameservers.contains(QStringLiteral("127.0.0.53"))) {
        const auto upstreams = parseResolvConf(QStringLiteral("/run/systemd/resolve/resolv.conf"));
        if (upstreams && !upstreams->nameservers.isEmpty()) nameservers = upstreams->nameservers;
    }
    QJsonObject resolvConf{{"nameservers", QJsonArray::fromStringList(nameservers)},
        {"search", QJsonArray::fromStringList(configuration->search)}};
    if (!configuration->domain.isEmpty()) resolvConf["domain"] = configuration->domain;
    QJsonObject data{{"resolv_conf", resolvConf}};
    const auto resolvectl = QStandardPaths::findExecutable(QStringLiteral("resolvectl"));
    if (!resolvectl.isEmpty())
        if (auto perLink = readResolvedPerLink(resolvectl)) data["resolved"] = *perLink;
    if (QJsonDocument(data).toJson(QJsonDocument::Compact).size() > LinuxDnsSnapshotBytes)
        return {{Status::Failed, "System resolver snapshot too large"}, {}};
    return {{}, data};
}
