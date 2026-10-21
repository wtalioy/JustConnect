#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "justconnect.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
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
    int finished = 0, ready = 0, rejected = 0, ticks = 0;
    ConnectionError lastError = ConnectionError::NONE;
    QObject::connect(&engine, &CoreEngine::authenticationRequired, &app, [&](const QJsonObject &event) {
        check(QThread::currentThread() == app.thread(), "authentication delivered on GUI thread");
        request = event;
    });
    QObject::connect(&engine, &CoreEngine::connectionEstablished, [&] { ++ready; });
    QObject::connect(&engine, &CoreEngine::responseRejected, [&] { ++rejected; });
    QObject::connect(&engine, &CoreEngine::finished, [&](ConnectionError error) { lastError = error; ++finished; });
    QObject::connect(&engine, &CoreEngine::diagnostic, [&](const QString &code) {
        check(!code.contains("private-"), "diagnostics do not disclose credentials");
    });
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(1);
#ifdef ABI_FIXTURE
    check(info["test_driver"].toBool(), "explicit test driver");
    check(engine.start(profile) && !engine.start(profile), "one active operation per adapter");
    until([&] { return !request.isEmpty() && ticks > 5; });
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
    engine.stop();
    until([&] { return finished == 1; });
    request = {};
    check(engine.start(profile), "restart accepted after cleanup");
    until([&] { return !request.isEmpty(); });
    check(request["generation"] == "2" && request["request_id"] == "2", "restart identity preserved as strings");
    engine.respond(answer);
    until([&] { return rejected == 3; });
    engine.respond(response(request, "cancel"));
    until([&] { return finished == 2; });

    for (int i = 0; i < 32; ++i) {
        auto *dying = new EmbeddedCoreEngine;
        bool destroyed = false;
        QObject::connect(dying, &CoreEngine::authenticationRequired, &app, [&](const QJsonObject &event) {
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
