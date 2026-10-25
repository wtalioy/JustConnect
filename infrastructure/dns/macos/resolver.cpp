#include "infrastructure/dns/macos/resolver.h"
#include <QDeadlineTimer>
#include <QDebug>
#include <QSet>
#include <QThread>

bool macDnsResolverMatches(const QString &configuration,const QString &peer,const QStringList &domains)
{
    if (peer.isEmpty() || domains.isEmpty()) return false;
    const QSet<QString> wanted(domains.begin(),domains.end());
    QSet<QString> ready;
    QString domain;
    QStringList servers;
    quint32 interface = 0;
    bool supplemental = false,scoped = false,conflict = false,block = false,unscoped = true;
    const auto finish = [&] {
        if (block && supplemental && wanted.contains(domain)) {
            if (!scoped && !interface && servers == QStringList{peer}) ready.insert(domain);
            else conflict = true;
        }
        domain.clear(); servers.clear(); interface = 0; supplemental = scoped = false;
    };
    for (const auto &raw : configuration.split('\n')) {
        const auto line = raw.trimmed();
        if (line.startsWith("resolver #")) { finish(); block = unscoped; continue; }
        if (line.startsWith("DNS configuration")) { finish(); block = false; unscoped = line == "DNS configuration"; continue; }
        if (!block) continue;
        const auto colon = line.indexOf(':');
        if (colon < 0) continue;
        const auto key = line.first(colon).trimmed(),value = line.mid(colon+1).trimmed();
        if (key == "domain") domain = value;
        else if (key.startsWith("nameserver[") && key.endsWith(']')) servers.append(value);
        else if (key == "if_index") interface = value.section(' ',0,0).toUInt();
        else if (key == "flags") {
            for (const auto &flag : value.split(',')) {
                supplemental |= flag.trimmed() == "Supplemental";
                scoped |= flag.trimmed() == "Scoped";
            }
        }
    }
    finish();
    return !conflict && ready == wanted;
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
