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
    profile.endpoint.protocol = "atrust";
    profile.endpoint.server = "127.0.0.1";
    profile.endpoint.port = 1;
    profile.credentials.password = QString::fromUtf8("private-验证");
    EmbeddedCoreEngine engine;
    QJsonObject request;
    int finished = 0, ready = 0, rejected = 0, ticks = 0;
    QObject::connect(&engine, &CoreEngine::authenticationRequired, &app, [&](const QJsonObject &event) {
        check(QThread::currentThread() == app.thread(), "authentication delivered on GUI thread");
        request = event;
    });
    QObject::connect(&engine, &CoreEngine::connectionEstablished, [&] { ++ready; });
    QObject::connect(&engine, &CoreEngine::responseRejected, [&] { ++rejected; });
    QObject::connect(&engine, &CoreEngine::finished, [&](ConnectionError) { ++finished; });
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
