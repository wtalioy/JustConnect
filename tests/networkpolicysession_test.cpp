#include "application/networkpolicysession.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QSemaphore>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

using Status = CoreEngine::RequestStatus;
using Kind = CoreEngine::Snapshot;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
template<class Predicate> static void until(Predicate ready)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!ready()) {
        check(elapsed.elapsed() < 5000, "Asynchronous model operation timed out");
        QCoreApplication::processEvents();
        QThread::msleep(1);
    }
}

class Engine : public CoreEngine
{
public:
    using CoreEngine::CoreEngine;
    QList<std::pair<Kind, QString>> requests;
    bool unsupported = false;
    bool start(const ConnectionProfile &, Operation) override { return true; }
    void stop() override { emit finished(ConnectionError::NONE); }
    void respond(const QJsonObject &) override {}
    void readSnapshot(Kind kind, const QString &id) override {
        requests.append({kind, id});
        if (unsupported) emit snapshotReady(kind, id, {}, Status::Unavailable);
    }
};

static QJsonObject network(const QString &address)
{
    return {{"network", QJsonObject{{"interfaces", QJsonArray{QJsonObject{{"addresses", QJsonArray{address + "/24"}}}}},
                                   {"routes", QJsonArray{}}}}};
}
static QJsonObject resources(const QString &address)
{
    return {{"resources", QJsonObject{{"ip_resources", QJsonArray{}},
                                      {"dns_records", QJsonObject{{"campus.test", QJsonArray{address}}}},
                                      {"campus_dns", ""}}}};
}
static void reply(Engine &engine, const QString &id, const QString &address)
{
    emit engine.snapshotReady(Kind::Network, id, network(address), Status::Success);
    emit engine.connectionEstablished();
    emit engine.snapshotReady(Kind::Resources, id, resources(address), Status::Success);
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    Engine engine;
    std::atomic_int reads = 0;
    QSemaphore resume;
    NetworkPolicySession session(&engine, [&] {
        const int read = ++reads;
        if (read == 1 || read == 4) check(resume.tryAcquire(1, 2000), "Release bounded DNS fixture");
        return DnsSnapshot{{}, {{"reader", read}, {"nrpt", QJsonArray{QJsonObject{{"Namespace", QJsonArray{QString(".generation%1.test").arg(read)}}}}}}};
    });
    int ticks = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(1);
    emit engine.sessionStarted("1");
    check(engine.requests.size() == 1 && engine.requests[0].first == Kind::Network,
          "Resources requested before transport readiness");
    reply(engine, "1", "192.168.1.19");
    until([&] { return reads == 1 && ticks > 3; });
    check(session.status() == Status::Pending && session.model().isEmpty() && !session.refresh(),
          "Incomplete model published or duplicate refresh accepted");
    session.clear();
    check(session.model().isEmpty() && session.status() == Status::Stale, "Clear retained old model");
    emit engine.sessionStarted("2");
    reply(engine, "2", "192.168.2.19");
    emit engine.snapshotReady(Kind::Network, "1", network("10.1.1.1"), Status::Success);
    emit engine.snapshotReady(Kind::Resources, "1", resources("10.1.1.1"), Status::Success);
    check(reads == 1, "Native DNS reads overlapped across generations");
    resume.release();
    until([&] { return session.status() == Status::Success; });
    check(!session.isBusy() && session.model()["generation"] == "2"
          && session.model()["dns"].toObject()["reader"] == 2
          && session.model()["dns_namespaces"].toArray().first().toObject()["name"] == ".generation2.test"
          && session.model()["network"].toObject() == network("192.168.2.19")["network"].toObject()
          && !session.model()["conflicts"].toArray().isEmpty(), "Old generation leaked into complete model");
    check(session.refresh(), "Ready session cannot refresh");
    reply(engine, "2", "192.168.3.19");
    until([&] { return session.status() == Status::Success; });
    check(session.model()["dns"].toObject()["reader"] == 3, "Refresh retained old DNS");
    emit engine.sessionStarted("3");
    reply(engine, "3", "192.168.4.19");
    until([&] { return reads == 4; });
    engine.stop();
    reply(engine, "3", "192.168.4.19");
    resume.release();
    until([&] { return !session.isBusy(); });
    check(session.model().isEmpty() && session.status() == Status::Stale, "Stopped session accepted late facts");

    Engine invalid;
    NetworkPolicySession malformed(&invalid, [] {
        return DnsSnapshot{{}, {{"nrpt", QJsonArray{QJsonObject{{"Namespace", "collapsed"}}}}}};
    });
    emit invalid.sessionStarted("1");
    emit invalid.snapshotReady(Kind::Network, "1", {}, Status::Success);
    emit invalid.connectionEstablished();
    emit invalid.snapshotReady(Kind::Resources, "1", resources("192.168.1.19"), Status::Success);
    until([&] { return !malformed.isBusy(); });
    check(malformed.status() == Status::Failed && malformed.model().isEmpty(), "Malformed success became usable model");
    check(malformed.refresh(), "Failed read cannot be refreshed");
    emit invalid.snapshotReady(Kind::Network, "1", network("192.168.1.19"), Status::Success);
    emit invalid.snapshotReady(Kind::Resources, "1", {{"resources", QJsonObject{}}}, Status::Success);
    until([&] { return !malformed.isBusy(); });
    check(malformed.status() == Status::Failed && malformed.model().isEmpty(), "Incomplete resources published partial model");
    check(malformed.refresh(), "Malformed DNS source cannot be refreshed");
    reply(invalid, "1", "192.168.1.19");
    until([&] { return !malformed.isBusy(); });
    check(malformed.status() == Status::Failed && malformed.model().isEmpty(), "Malformed DNS source published usable network facts");
    invalid.unsupported = true;
    check(malformed.refresh(), "Capability failure cannot be refreshed");
    until([&] { return !malformed.isBusy(); });
    check(malformed.status() == Status::Unavailable && malformed.model().isEmpty(), "Missing capability misreported");

    Engine throwing;
    NetworkPolicySession failed(&throwing, []() -> DnsSnapshot { throw std::runtime_error("private native failure"); });
    emit throwing.sessionStarted("1");
    reply(throwing, "1", "192.168.1.19");
    until([&] { return !failed.isBusy(); });
    check(failed.status() == Status::Failed && failed.model().isEmpty(), "Reader exception escaped or exposed partial facts");

    auto borrowed = std::make_unique<Engine>();
    NetworkPolicySession detached(borrowed.get(), {});
    emit borrowed->sessionStarted("1");
    reply(*borrowed, "1", "192.168.1.19");
    check(detached.status() == Status::Unavailable && detached.model().isEmpty(), "Missing native reader treated as empty DNS");
    borrowed.reset();
    check(detached.status() == Status::Stale && !detached.refresh(), "Destroyed engine retained a usable model or request path");

    Engine closing;
    QSemaphore entered, finish;
    auto owned = std::make_unique<NetworkPolicySession>(&closing, [&] {
        entered.release();
        check(finish.tryAcquire(1, 2000), "Release destruction fixture");
        return DnsSnapshot{{}, {{"owned", true}}};
    });
    emit closing.sessionStarted("1");
    reply(closing, "1", "192.168.1.19");
    until([&] { return entered.available() != 0; });
    owned->clear();
    std::thread release([&] { QThread::msleep(20); finish.release(); });
    owned.reset();
    release.join();
    QCoreApplication::processEvents();
    std::cout << "PASS: generation-bound complete model, responsive GUI, bounded serialized DNS, stale results and owned destruction\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
