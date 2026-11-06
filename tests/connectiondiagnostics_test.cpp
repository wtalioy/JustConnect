#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "application/systemproxysession.h"
#include "presentation/coordinators/connectiondiagnostics.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>
#include <iostream>
#include <stdexcept>

static void check(bool okay, const char *message)
{
    if (!okay)
        throw std::runtime_error(message);
}
class Engine final : public CoreEngine
{
  public:
    int starts = 0, reads = 0;
    bool start(const ConnectionProfile &, Operation) override
    {
        emit sessionStarted(QString::number(++starts));
        return true;
    }
    void stop() override
    {
        emit finished(ConnectionError::NONE);
    }
    void respond(const QJsonObject &) override
    {
    }
    void readSnapshot(Snapshot kind, const QString &id) override
    {
        ++reads;
        if (kind == Snapshot::Network)
            emit snapshotReady(kind, id,
                               {{"schema_version", 1},
                                {"network", QJsonObject{{"interfaces", QJsonArray{}}, {"routes", QJsonArray{}}}}},
                               RequestStatus::Success);
        else if (kind == Snapshot::Resources)
            emit snapshotReady(
                kind, id,
                {{"resources",
                  QJsonObject{{"ip_resources", QJsonArray{}},
                              {"domain_resources", QJsonObject{}},
                              {"dns_records", QJsonObject{}},
                              {"campus_dns", "192.0.2.53"},
                              {"campus_dns_enabled", true},
                              {"secret", "do-not-export"},
                              {"listeners", QJsonObject{{"http", "127.0.0.1:18080"},
                                                        {"socks", "user:do-not-export@127.0.0.1:18081"}}}}}},
                RequestStatus::Success);
    }
};
class Network final : public NetworkAccess
{
  public:
    void prepare(const QUuid &id) override
    {
        emit prepared(id, {});
    }
    void activate(const QUuid &id, const ConnectionProfile &) override
    {
        emit ready(id, {});
    }
    void stop(const QUuid &id) override
    {
        emit quiesced(id);
        emit stopped(id, {});
    }
};
class Proxy final : public SystemProxyBackend
{
  public:
    SystemProxyCheck check(const SystemProxyConfig &) override
    {
        return {};
    }
    PlatformOperationResult apply(const SystemProxyConfig &) override
    {
        return {};
    }
    PlatformOperationResult clear() override
    {
        return {};
    }
};
int main(int argc, char **argv)
try
{
    QCoreApplication app(argc, argv);
    auto *engine = new Engine;
    auto *network = new Network;
    ConnectionSession connection(engine, nullptr, network);
    NetworkPolicySession policy(engine, [] { return DnsSnapshot{}; });
    SystemProxySession proxy(std::make_unique<Proxy>());
    ConnectionDiagnostics diagnostics(engine, &connection, &policy, &proxy);
    check(diagnostics.report().contains("Unknown") && engine->reads == 0,
          "unknown diagnostics must not imply readiness or start probes");
    check(connection.start({}, {}), "start the diagnostic session");
    emit engine->connectionEstablished();
    QElapsedTimer elapsed;
    elapsed.start();
    while (policy.isBusy() && elapsed.elapsed() < 5000)
    {
        app.processEvents();
        QThread::msleep(1);
    }
    check(policy.status() == CoreEngine::RequestStatus::Success, "confirm the actual shared policy model");
    auto report = diagnostics.report();
    check(report.contains("System capture: Ready") && report.contains("HTTP 18080") &&
              report.contains("campus 192.0.2.53") && report.contains("Routing policy:") &&
              !report.contains("do-not-export"),
          "diagnostics must show confirmed ports, DNS and policy while excluding credentials and unrecognized fields");
    QStringList visible;
    for (const auto &[label,value]:diagnostics.fields()) visible.append(label+": "+value);
    check(visible.join('\n')==report,"the visible fields and copied report use the same redacted evidence");
    const auto observation = [](const QString &mode) {
        return QJsonObject{
            {"schema_version", 1},
            {"coexistence",
             QJsonObject{
                 {"active", true}, {"available", true}, {"tun", true}, {"mode", mode}, {"secret", "do-not-export"}}}};
    };
    emit engine->snapshotReady(CoreEngine::Snapshot::Coexistence, "1", observation("rule"),
                               CoreEngine::RequestStatus::Success);
    check(diagnostics.report().contains("Clash rule · TUN On"),
          "a confirmed coexistence observation must explain the ordinary exit");
    emit engine->snapshotReady(CoreEngine::Snapshot::Coexistence, "old", observation("global"),
                               CoreEngine::RequestStatus::Success);
    check(diagnostics.report().contains("Clash rule"), "a late observation cannot overwrite the current generation");
    emit engine->snapshotReady(CoreEngine::Snapshot::Coexistence, "1", observation(""),
                               CoreEngine::RequestStatus::Success);
    check(diagnostics.report().contains("Ordinary exit: Unknown"),
          "an incomplete active observation cannot confirm an exit");
    emit engine->snapshotReady(CoreEngine::Snapshot::Coexistence, "1", observation("rule"),
                               CoreEngine::RequestStatus::Success);
    emit connection.diagnostic("coexistence_refresh_failed");
    check(diagnostics.report().contains("Ordinary exit: Unknown"),
          "failed observation cannot retain a confirmed exit claim");
    emit connection.diagnostic("user:do-not-export");
    check(!diagnostics.report().contains("do-not-export"), "unstructured messages cannot enter the diagnostic export");
    const auto reads = engine->reads;
    for (int i = 0; i < 20; ++i)
        diagnostics.report();
    check(engine->reads == reads, "rendering diagnostics must not create network reads or polling");
    connection.stop();
    report = diagnostics.report();
    check(report.contains("System capture: Not active") && !report.contains("HTTP 18080"),
          "disconnect clears stale entry and policy evidence");
    std::cout << "PASS: current-generation diagnostic evidence, redaction, failed observation and passive rendering\n";
    return 0;
}
catch (const std::exception &error)
{
    std::cerr << error.what() << '\n';
    return 1;
}
