#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "justconnect.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QList>
#include <QTimer>
#include <cstdlib>
#include <iostream>

static void check(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
template<class Predicate> static void until(Predicate done) {
    QElapsedTimer timer;
    timer.start();
    while (!done() && timer.elapsed() < 10000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    check(done(), "Qt event delivery timed out");
}
static QJsonObject response(const QJsonObject &request, const QString &action = "submit") {
    return {{"schema_version", int(JC_ABI_VERSION)}, {"generation", request["generation"]},
        {"request_id", request["request_id"]}, {"action", action}};
}
static QJsonObject policy(const QString &generation, const QString &revision) {
    return {{"schema_version",int(JC_ABI_VERSION)},{"generation",generation},{"revision",revision},
        {"protected",QJsonArray{"192.168.50.0/24"}},{"campus",QJsonArray{}}};
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const auto info = EmbeddedCoreEngine::buildInfo();
    check(info["abi_version"].toInt() == JC_ABI_VERSION, "loaded library ABI metadata");
    ConnectionProfile profile;
    profile.endpoint.server = "127.0.0.1";
    profile.endpoint.port = 1;
    profile.credentials.password = QString::fromUtf8("private-验证");
    EmbeddedCoreEngine engine;
    QJsonObject request;
    QString generation;
    QList<CoreEngine::RequestStatus> policyReplies;
    QList<CoreEngine::RequestStatus> snapshotReplies;
    QJsonObject lastSnapshot;
    int finished = 0, ready = 0, rejected = 0, ticks = 0;
    ConnectionError lastError = ConnectionError::NONE;
    QObject::connect(&engine, &CoreEngine::authenticationRequired, &app, [&](const QJsonObject &event) {
        check(QThread::currentThread() == app.thread(), "authentication delivered on GUI thread");
        request = event;
    });
    QObject::connect(&engine, &CoreEngine::connectionEstablished, [&] { ++ready; });
    QObject::connect(&engine, &CoreEngine::responseRejected, [&] { ++rejected; });
    QObject::connect(&engine, &CoreEngine::finished, [&](ConnectionError error) { lastError = error; ++finished; });
    QObject::connect(&engine, &CoreEngine::sessionStarted, [&](const QString &value) { generation = value; });
    QObject::connect(&engine, &CoreEngine::policyUpdated, [&](const QString &applied, const QString &revision, CoreEngine::RequestStatus status) {
        check(QThread::currentThread() == app.thread() && !applied.isEmpty() && !revision.isEmpty(), "policy acknowledgement reaches the GUI with its identity");
        policyReplies.append(status);
    });
    QObject::connect(&engine, &CoreEngine::snapshotReady, [&](CoreEngine::Snapshot, const QString &value, const QJsonObject &snapshot, CoreEngine::RequestStatus status) {
        check(QThread::currentThread() == app.thread() && !value.isEmpty(), "snapshot result reaches the GUI with its generation");
        if (status != CoreEngine::RequestStatus::Success) check(snapshot.isEmpty(), "unsuccessful snapshot cannot carry old data");
        lastSnapshot = snapshot;
        snapshotReplies.append(status);
    });
    QObject::connect(&engine, &CoreEngine::diagnostic, [&](const QString &code) {
        check(!code.contains("private-"), "diagnostics do not disclose credentials");
    });
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(1);
#ifdef ABI_FIXTURE
    check(info["test_driver"].toBool(), "explicit test driver");
    check(info["capabilities"].toObject()["policy_update"].toBool(), "policy capability advertised");
    engine.updatePolicy(policy("1","1"));
    check(policyReplies.last() == CoreEngine::RequestStatus::Stale, "idle adapter rejects policy without starting a core");
    engine.readSnapshot(CoreEngine::Snapshot::Network,"1");
    check(snapshotReplies.last() == CoreEngine::RequestStatus::Stale, "idle adapter rejects an unscoped snapshot");
    check(engine.start(profile) && !engine.start(profile), "one active operation per adapter");
    until([&] { return !request.isEmpty() && ticks > 5; });
    check(generation == request["generation"].toString(), "authoritative generation is available without an authentication response");
    auto readSnapshot = [&](CoreEngine::Snapshot kind, const QString &value, CoreEngine::RequestStatus expected) {
        const auto before = snapshotReplies.size();
        engine.readSnapshot(kind,value);
        until([&] { return snapshotReplies.size() == before+1; });
        check(snapshotReplies.last() == expected, "Qt snapshot classification");
    };
    readSnapshot(CoreEngine::Snapshot::Network,generation,CoreEngine::RequestStatus::Success);
    check(!lastSnapshot["network"].toObject()["interfaces"].toArray().isEmpty(), "native network snapshot reaches the Qt consumer");
    readSnapshot(CoreEngine::Snapshot::Resources,generation,CoreEngine::RequestStatus::Unavailable);
    readSnapshot(CoreEngine::Snapshot::Network,"2",CoreEngine::RequestStatus::Stale);
    auto update = [&](QJsonObject fields, CoreEngine::RequestStatus expected) {
        const auto before = policyReplies.size();
        engine.updatePolicy(fields);
        until([&] { return policyReplies.size() == before + 1; });
        check(policyReplies.last() == expected, "Qt policy acknowledgement classification");
    };
    update(policy(generation,"2"), CoreEngine::RequestStatus::Success);
    update(policy(generation,"1"), CoreEngine::RequestStatus::Stale);
    auto invalid = policy(generation,"3"); invalid["protected"] = QJsonArray{"192.168.50.1/24"};
    update(invalid, CoreEngine::RequestStatus::Invalid);
    update(policy(generation,"3"), CoreEngine::RequestStatus::Success);
    update(policy("0","4"), CoreEngine::RequestStatus::Invalid);
    update(policy("2","4"), CoreEngine::RequestStatus::Stale);
    auto answer = response(request);
    answer["code"] = profile.credentials.password;
    auto stale = answer;
    stale["generation"] = "0";
    engine.respond(stale);
    until([&] { return rejected == 1; });
    engine.respond(answer);
    until([&] { return ready == 1; });
    engine.respond(answer);
    until([&] { return rejected == 2; });
    const auto beforeStop = policyReplies.size();
    const auto snapshotsBeforeStop = snapshotReplies.size();
    engine.readSnapshot(CoreEngine::Snapshot::Network,generation);
    engine.updatePolicy(policy(generation,"4"));
    engine.stop();
    until([&] { return finished == 1; });
    until([&] { return policyReplies.size() == beforeStop + 1; });
    check(policyReplies.last() == CoreEngine::RequestStatus::Stale, "queued success cannot claim active policy after stop");
    until([&] { return snapshotReplies.size() == snapshotsBeforeStop+1; });
    check(snapshotReplies.last() == CoreEngine::RequestStatus::Stale && lastSnapshot.isEmpty(), "queued snapshot is discarded after stop");
    request = {};
    check(engine.start(profile), "restart accepted after cleanup");
    until([&] { return !request.isEmpty(); });
    check(request["generation"] == "2" && request["request_id"] == "2", "restart identity preserved as strings");
    update(policy("1","5"), CoreEngine::RequestStatus::Stale);
    update(policy(generation,"1"), CoreEngine::RequestStatus::Success);
    engine.respond(answer);
    until([&] { return rejected == 3; });
    engine.respond(response(request, "cancel"));
    until([&] { return finished == 2; });

    for (int i = 0; i < 32; ++i) {
        auto *dying = new EmbeddedCoreEngine;
        bool destroyed = false;
        QObject::connect(dying, &CoreEngine::authenticationRequired, &app, [&](const QJsonObject &event) {
            dying->readSnapshot(CoreEngine::Snapshot::Network,event["generation"].toString());
            dying->updatePolicy(policy(event["generation"].toString(),"1"));
            dying->respond(response(event, "cancel"));
            delete dying;
            destroyed = true;
        });
        check(dying->start(profile), "start before queued response and destruction");
        until([&] { return destroyed; });
    }
#else
    check(!info["test_driver"].toBool() && info["capabilities"].toObject()["embedded_vpn"].toBool(), "production backend");
    for (int i = 0; i < 16; ++i) {
        check(engine.start(profile), "production asynchronous start");
        engine.stop();
        until([&] { return finished == i + 1; });
    }
#endif
    check(EmbeddedCoreEngine::validateConfiguration(profile) == ConnectionError::NONE, "pure Qt configuration validation");
    for (int i = 0; i < 13; ++i) {
        auto invalid = profile;
        switch (i) {
        case 0: invalid.endpoint.server = "https://invalid.example.edu"; break;
        case 1: invalid.endpoint.authType = "unsupported"; break;
        case 2: invalid.dns.localDnsServer = "invalid:port"; break;
        case 3: invalid.proxy.socksBind = "0.0.0.0:1080"; break;
        case 4: invalid.endpoint.port = 0; break;
        case 5: invalid.tls.caPem="not a certificate"; break;
        case 6: invalid.tls.caPem=QString(65536,'x'); break;
        case 7: invalid.behavior.rememberAuthentication=true;invalid.authenticationCache.account="owner";break;
        case 8: invalid.behavior.rememberAuthentication=true;invalid.authenticationCache.data="unbound";break;
        case 9: invalid.behavior.rememberAuthentication=true;invalid.authenticationCache={"owner",QByteArray(JC_MAX_AUTH_CACHE+1,'x')};break;
        case 10: invalid.keepAlive.mode="unsupported";break;
        case 11: invalid.keepAlive={"target","ssh://campus.example.invalid:22"};break;
        case 12: invalid.keepAlive={"target","https://campus.example.invalid/logout?token=private-value"};break;
        }
        check(EmbeddedCoreEngine::validateConfiguration(invalid) == ConnectionError::INVALID_CONFIGURATION, "saving and starting share strict configuration rules");
        const int before = finished;
        check(engine.start(invalid), "invalid configuration is reported asynchronously");
        until([&] { return finished == before + 1; });
        check(lastError == ConnectionError::INVALID_CONFIGURATION, "unsafe or unsupported configuration is rejected");
    }
    for (const auto &mode:QStringList{"auto","off","target"}) {
        auto keepAlive=profile;keepAlive.keepAlive={mode,"https://campus.example.invalid/status"};
        check(EmbeddedCoreEngine::validateConfiguration(keepAlive)==ConnectionError::NONE,"safe traffic keepalive settings reach the formal core validator");
    }
    // Destroy immediately while start/read may still be queued; then reuse the global slot.
    for (int i = 0; i < 32; ++i) {
        auto *dying = new EmbeddedCoreEngine;
        dying->start(profile);
        delete dying;
    }
    const int before = finished;
    check(engine.start(profile), "slot available after repeated destruction");
    engine.stop();
    until([&] { return finished == before + 1; });
    std::cout << "PASS: Qt adapter ownership, queued delivery, cancellation and destruction\n";
}
