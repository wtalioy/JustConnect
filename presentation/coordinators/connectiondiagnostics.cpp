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
        confirmedModel = {};
        exitKnown = false;
        mode.clear();
        code.clear();
        emit changed();
    });
    connect(core, &CoreEngine::finished, this, [this] {
        generation.clear();
        confirmedModel = {};
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
                            state["tun"].isBool() &&
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
                                         "tls_authentication_failed",      "persistence_failed",
                                         "browser_proxy_changed_externally", "browser_proxy_observation_unavailable",
                                         "browser_proxy_settings_unsupported", "browser_proxy_listener_unverified",
                                         "browser_proxy_endpoint_mismatch", "browser_proxy_inactive"};
        code = known.contains(value) ? value : QString();
        if (value == "coexistence_refresh_failed")
            exitKnown = false;
        emit changed();
    });
    connect(connection, &ConnectionSession::stateChanged, this, &ConnectionDiagnostics::changed);
    connect(connection, &ConnectionSession::progressChanged, this, &ConnectionDiagnostics::changed);
    connect(policy, &NetworkPolicySession::changed, this, [this] {
        const bool current = !generation.isEmpty() && this->policy->currentGeneration() == generation;
        // A read in flight keeps the last confirmed display; errors and generation changes invalidate it.
        if (!current || this->policy->status() != CoreEngine::RequestStatus::Pending)
            confirmedModel = current && this->policy->status() == CoreEngine::RequestStatus::Success
                ? this->policy->model() : QJsonObject{};
        emit changed();
    });
    connect(proxy, &SystemProxySession::busyChanged, this, &ConnectionDiagnostics::changed);
    connect(proxy, &SystemProxySession::enabledChanged, this, &ConnectionDiagnostics::changed);
}

QList<QPair<QString,QString>> ConnectionDiagnostics::fields() const
{
    const auto unknown = tr("Unknown");
    if (!connection || !policy || !proxy)
        return {};
    const auto model = confirmedModel;
    const bool confirmed = !generation.isEmpty() && policy->currentGeneration() == generation &&
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
    QList<QPair<QString,QString>> result{{tr("System capture"),capture},
        {tr("Local entry"),tr("HTTP %1 · SOCKS %2").arg(endpoint("http"),endpoint("socks"))}};
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
    result.append({tr("DNS sources"),dns});
    const auto rules = confirmed ? tr("%1 IP rules · %2 domain patterns · %3 protected scopes · %4 overlaps")
                                       .arg(resources["ip_resources"].toArray().size())
                                       .arg(resources["domain_resources"].toObject().size())
                                       .arg(model["targets"].toArray().size())
                                       .arg(model["conflicts"].toArray().size())
                                 : unknown;
    result.append({tr("Routing policy"),rules});
    if (confirmed)
        result.append({tr("Campus exceptions"),tr("%1 addresses · %2 names")
                         .arg(policy->campusAddresses().size()).arg(policy->campusNames().size())});
    result.append({tr("Campus exit"),ready ? tr("Campus tunnel") : unknown});
    const auto ordinary = !exitKnown    ? unknown
                          : clashActive ? tr("Clash %1 · TUN %2").arg(mode, tun ? tr("On") : tr("Off"))
                                        : tr("System routing");
    result.append({tr("Ordinary exit"),ordinary});
    const auto recovery = connection->networkRecoveryFailed() ? tr("Retry network recovery")
                          : proxy->isBusy() || connection->phase() == ConnectionPhase::NetworkRestoring
                              ? tr("In progress")
                          : proxy->needsCleanup() ? tr("Browser proxy ownership retained")
                                                  : tr("No pending browser restoration");
    result.append({tr("Recovery"),recovery});
    if (!code.isEmpty())
        result.append({tr("Diagnostic code"),code});
    return result;
}

QString ConnectionDiagnostics::report() const
{
    QStringList lines;
    for (const auto &[label,value]:fields()) lines.append(label+": "+value);
    return lines.isEmpty() ? tr("Unknown") : lines.join('\n');
}
