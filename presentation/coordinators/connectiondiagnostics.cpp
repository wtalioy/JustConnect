#include "connectiondiagnostics.h"
#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "application/systemproxysession.h"
#include <QHostAddress>
#include <QSet>
#include <QUrl>

ConnectionDiagnostics::ConnectionDiagnostics(CoreEngine *core, ConnectionSession *connection,
                                             NetworkPolicySession *policy, SystemProxySession *proxy, QObject *parent)
    : QObject(parent), connection(connection), policy(policy), proxy(proxy)
{
    connect(core, &CoreEngine::sessionStarted, this, [this](const QString &id) {
        generation = id;
        exitKnown = false;
        mode.clear();
        code.clear();
        emit changed();
    });
    connect(core, &CoreEngine::finished, this, [this] {
        generation.clear();
        exitKnown = false;
        mode.clear();
        emit changed();
    });
    connect(core, &CoreEngine::snapshotReady, this,
            [this](CoreEngine::Snapshot kind, const QString &id, const QJsonObject &snapshot,
                   CoreEngine::RequestStatus status) {
                if (kind != CoreEngine::Snapshot::Coexistence || generation.isEmpty() || id != generation)
                    return;
                const auto state = snapshot["coexistence"].toObject();
                const auto observed = state["mode"].toString();
                exitKnown = status == CoreEngine::RequestStatus::Success &&
                            snapshot["schema_version"].toInteger() > 0 && state["active"].isBool() &&
                            state["tun"].isBool() && !state.contains("listener_request") &&
                            (!state["active"].toBool() || (state["available"].toBool() && !observed.isEmpty())) &&
                            (observed.isEmpty() || observed == "rule" || observed == "global" || observed == "direct");
                mode = exitKnown ? observed : QString();
                clashActive = exitKnown && state["active"].toBool();
                tun = exitKnown && state["tun"].toBool();
                emit changed();
            });
    connect(connection, &ConnectionSession::diagnostic, this, [this](const QString &value) {
        static const QSet<QString> known{"authentication_started",         "transport_connected",
                                         "local_controller_real_dns",      "local_controller_ambiguous",
                                         "local_controller_unavailable",   "coexistence_refresh_failed",
                                         "tls_node_verification_disabled", "tls_verification_disabled",
                                         "tls_authentication_failed",      "persistence_failed"};
        code = known.contains(value) ? value : QString();
        if (value == "coexistence_refresh_failed")
            exitKnown = false;
        emit changed();
    });
    connect(connection, &ConnectionSession::stateChanged, this, &ConnectionDiagnostics::changed);
    connect(connection, &ConnectionSession::progressChanged, this, &ConnectionDiagnostics::changed);
    connect(policy, &NetworkPolicySession::changed, this, &ConnectionDiagnostics::changed);
    connect(proxy, &SystemProxySession::busyChanged, this, &ConnectionDiagnostics::changed);
    connect(proxy, &SystemProxySession::enabledChanged, this, &ConnectionDiagnostics::changed);
}

QString ConnectionDiagnostics::report() const
{
    const auto unknown = tr("Unknown");
    if (!connection || !policy || !proxy)
        return unknown;
    const auto model = policy->model();
    const bool confirmed = !generation.isEmpty() && policy->currentGeneration() == generation &&
                           policy->status() == CoreEngine::RequestStatus::Success &&
                           model["schema_version"].toInteger() > 0;
    const auto resources = confirmed ? model["resources"].toObject() : QJsonObject();
    const auto endpoint = [&](const QString &key) {
        const auto listeners = resources["listeners"].toObject();
        if (!confirmed || !listeners.contains(key))
            return unknown;
        const auto value = listeners[key].toString();
        if (value.isEmpty())
            return tr("Off");
        const QUrl url("http://" + value);
        const QHostAddress address(url.host());
        if (!address.isLoopback() || !url.userInfo().isEmpty() || !url.path().isEmpty() || !url.query().isEmpty() ||
            !url.fragment().isEmpty() || url.port() < 1 || url.port() > 65535)
            return unknown;
        return url.port() > 0 ? QString::number(url.port()) : unknown;
    };
    const bool ready =
        connection->state() == ConnectionState::Running && connection->phase() == ConnectionPhase::CampusReady;
    const auto capture = connection->networkRecoveryFailed() ? tr("Recovery required")
                         : ready                             ? tr("Ready")
                         : connection->isActive()            ? tr("In progress")
                                                             : tr("Not active");
    QStringList lines{tr("System capture: %1").arg(capture),
                      tr("Local entry ports: HTTP %1 · SOCKS %2").arg(endpoint("http"), endpoint("socks"))};
    QString dns = unknown;
    if (confirmed)
    {
        const QHostAddress server(resources["campus_dns"].toString());
        const auto campus = !resources["campus_dns_enabled"].toBool() ? tr("Off")
                            : server.isNull()                         ? unknown
                                                                      : server.toString();
        dns = tr("campus %1 · %2 original scopes · %3 domain DNS rules")
                  .arg(campus)
                  .arg(model["dns_namespaces"].toArray().size())
                  .arg(resources["domain_dns_names"].toArray().size());
    }
    lines.append(tr("DNS sources: %1").arg(dns));
    const auto rules = confirmed ? tr("%1 IP rules · %2 domain patterns · %3 protected scopes · %4 overlaps")
                                       .arg(resources["ip_resources"].toArray().size())
                                       .arg(resources["domain_resources"].toObject().size())
                                       .arg(model["targets"].toArray().size())
                                       .arg(model["conflicts"].toArray().size())
                                 : unknown;
    lines.append(tr("Confirmed routing policy: %1").arg(rules));
    if (confirmed)
        lines.append(tr("Campus exceptions: %1 addresses · %2 names")
                         .arg(policy->campusAddresses().size())
                         .arg(policy->campusNames().size()));
    lines.append(tr("Campus exit: %1").arg(ready ? tr("Campus tunnel") : unknown));
    const auto ordinary = !exitKnown    ? unknown
                          : clashActive ? tr("Clash %1 · TUN %2").arg(mode, tun ? tr("On") : tr("Off"))
                                        : tr("System routing");
    lines.append(tr("Ordinary exit: %1").arg(ordinary));
    const auto recovery = connection->networkRecoveryFailed() ? tr("Retry network recovery")
                          : proxy->isBusy() || connection->phase() == ConnectionPhase::NetworkRestoring
                              ? tr("In progress")
                          : proxy->needsCleanup() ? tr("Browser proxy ownership retained")
                                                  : tr("No pending browser restoration");
    lines.append(tr("Recovery: %1").arg(recovery));
    if (!code.isEmpty())
        lines.append(tr("Diagnostic code: %1").arg(code));
    return lines.join('\n');
}
