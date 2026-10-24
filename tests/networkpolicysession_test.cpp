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
    QList<QJsonObject> policies;
    bool start(const ConnectionProfile &, Operation) override { return true; }
    void stop() override { emit finished(ConnectionError::NONE); }
    void respond(const QJsonObject &) override {}
    void updatePolicy(const QJsonObject &policy) override { policies.append(policy); }
    void readSnapshot(Kind kind, const QString &id) override {
        requests.append({kind, id});
        if (unsupported) emit snapshotReady(kind, id, {}, Status::Unavailable);
    }
};

static QJsonObject network(const QString &address)
{
    return {{"schema_version", 1}, {"network", QJsonObject{{"interfaces", QJsonArray{QJsonObject{{"addresses", QJsonArray{address + "/24"}}}}},
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

static void ownershipViewsStaySerializedAndGenerationBound()
{
    Engine engine;
    std::atomic_int reads = 0;
    QSemaphore entered, resume;
    NetworkPolicySession session(&engine, [&] {
        if (++reads == 2) {
            entered.release();
            check(resume.tryAcquire(1, 2000), "Release ownership projection fixture");
        }
        return DnsSnapshot{};
    });
    emit engine.sessionStarted("owned");
    reply(engine, "owned", "192.168.10.19");
    until([&] { return !session.isBusy(); });
    const auto requests = engine.requests.size();
    session.setNetworkBusy("stale", true);
    check(!session.isBusy(), "Old ownership operation changed the current model");
    session.setNetworkBusy("owned", true);
    check(session.isBusy() && !session.refresh() && !session.setCampusAddress("192.168.10.20", true)
          && !session.setCampusName("campus.test", true) && engine.policies.isEmpty(),
          "A changing owned network allowed new reads or policy choices");
    const auto select = [](const QString &marker) -> NetworkPolicySession::OriginalViewFilter {
        return [marker](QJsonObject network, QJsonObject dns) -> std::optional<NetworkPolicySession::OriginalView> {
            network["interfaces"] = QJsonArray{};
            network["owned_filter"] = marker;
            return NetworkPolicySession::OriginalView{network, dns};
        };
    };
    session.setOriginalViewFilter("owned", select("first"));
    check(engine.requests.size() == requests && session.model().isEmpty(), "Projection changed facts during an active network operation");
    session.setNetworkBusy("owned", false);
    check(engine.requests.size() == requests + 2, "Settled ownership did not refresh both native snapshots");
    reply(engine, "owned", "192.168.10.19");
    until([&] { return entered.available() != 0; });
    session.setNetworkBusy("owned", true);
    session.setOriginalViewFilter("owned", select("latest"));
    session.setNetworkBusy("owned", false);
    check(engine.requests.size() == requests + 2 && session.isBusy(), "Ownership change overlapped a native DNS reader");
    resume.release();
    until([&] { return engine.requests.size() == requests + 4; });
    const auto original = network("192.168.11.19");
    emit engine.snapshotReady(Kind::Network, "owned", original, Status::Success);
    emit engine.snapshotReady(Kind::Resources, "owned", resources("192.168.11.19"), Status::Success);
    until([&] { return !session.isBusy(); });
    check(session.status() == Status::Success && session.model()["network"].toObject()["owned_filter"] == "latest"
          && session.model()["targets"].toArray().size() == 2
          && !original["network"].toObject()["interfaces"].toArray().isEmpty(),
          "Old projection won, owned scopes survived, or the original input was mutated");
    emit engine.sessionStarted("next");
    session.setNetworkBusy("owned", true);
    session.setOriginalViewFilter("owned", select("stale"));
    reply(engine, "next", "192.168.12.19");
    until([&] { return !session.isBusy(); });
    check(session.status() == Status::Success && !session.model()["network"].toObject().contains("owned_filter")
          && session.model()["targets"].toArray().size() == 3, "New generation inherited previous ownership");
    session.setOriginalViewFilter("next", [](const QJsonObject &, const QJsonObject &) -> std::optional<NetworkPolicySession::OriginalView> { return {}; });
    reply(engine, "next", "192.168.12.19");
    until([&] { return !session.isBusy(); });
    check(session.status() == Status::Failed && session.model().isEmpty() && engine.policies.isEmpty(),
          "Failed ownership projection published partial facts or changed the core policy");
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    ownershipViewsStaySerializedAndGenerationBound();
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
    const QJsonArray initialNames{QJsonObject{{"kind", "suffix"}, {"value", "confirmed.native.test"}}};
    const QJsonObject initialPolicy{{"schema_version", 1}, {"generation", "2"}, {"revision", "0"},
        {"protected", QJsonArray{"127.0.0.0/8"}}, {"campus", QJsonArray{}},
        {"protected_names", initialNames}, {"campus_names", QJsonArray{}}};
    emit engine.initialProtectionApplied(initialPolicy);
    auto staleInitial = initialPolicy;
    staleInitial["generation"] = "1";
    staleInitial["protected_names"] = QJsonArray{};
    emit engine.initialProtectionApplied(staleInitial);
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
    for (const auto &bad : {"8.8.8.8", "192.168.2.999", "192.168.2.020", "::1", "::ffff:192.168.2.20"})
        check(!session.setCampusAddress(bad, true) && session.policyStatus() == Status::Invalid,
              "Campus choice accepted an ambiguous, unsupported or unprotected address");
    check(engine.policies.isEmpty(), "Invalid campus choice reached the core");
    check(session.setCampusAddress("192.168.2.20", true) && session.isBusy()
          && session.campusAddresses().isEmpty() && !session.refresh()
          && !session.setCampusAddress("192.168.2.21", true), "Unconfirmed choice published or writes overlapped");
    const auto firstPolicy = engine.policies.last();
    QJsonArray originalPrefixes;
    for (const auto &value : session.model()["targets"].toArray()) originalPrefixes.append(value.toObject()["prefix"]);
    check(firstPolicy["schema_version"] == 1 && firstPolicy["generation"] == "2" && firstPolicy["revision"] == "1"
          && firstPolicy["protected"].toArray() == originalPrefixes
          && firstPolicy["protected_names"].toArray() == initialNames
          && firstPolicy["campus_names"].toArray().isEmpty()
          && firstPolicy["campus"].toArray() == QJsonArray{"192.168.2.20"}, "Choice lost its complete native scopes or wire identity");
    emit engine.policyUpdated("1", "1", Status::Success);
    emit engine.policyUpdated("2", "99", Status::Success);
    check(session.isBusy() && session.campusAddresses().isEmpty(), "Unrelated acknowledgement applied a pending choice");
    emit engine.policyUpdated("2", "1", Status::Success);
    check(!session.isBusy() && session.policyStatus() == Status::Success
          && session.campusAddresses() == QJsonArray{"192.168.2.20"}, "Matching acknowledgement did not publish actual choice");
    check(session.setCampusAddress("192.168.2.20", true) && engine.policies.size() == 1, "Repeated choice wrote another policy");
    check(session.setCampusAddress("192.168.2.21", true), "Second exact campus choice rejected");
    emit engine.policyUpdated("2", "2", Status::Failed);
    check(session.policyStatus() == Status::Failed && session.campusAddresses() == QJsonArray{"192.168.2.20"},
          "Failed replacement overwrote the last effective selection");
    check(session.refresh(), "Ready session cannot refresh");
    reply(engine, "2", "192.168.3.19");
    until([&] { return session.status() == Status::Success; });
    check(session.model()["dns"].toObject()["reader"] == 3, "Refresh retained old DNS");
    check(!session.setCampusAddress("192.168.2.21", true), "Refreshed scopes allowed a new exception outside the current network");
    check(session.setCampusAddress("192.168.2.20", false), "Return to original network rejected");
    check(engine.policies.last()["revision"] == "3" && engine.policies.last()["campus"].toArray().isEmpty(),
          "Return failed to remove the exception with a fresh revision");
    emit engine.policyUpdated("2", "3", Status::Success);
    check(session.campusAddresses().isEmpty() && !session.isBusy(), "Confirmed original preference retained an exception");
    check(session.setCampusAddress("192.168.3.20", true), "Choice after refresh rejected");
    check(engine.policies.last()["revision"] == "4"
          && engine.policies.last()["protected_names"].toArray() == initialNames,
          "Refresh reset the revision or implicitly replaced confirmed name protection");
    emit engine.sessionStarted("3");
    emit engine.policyUpdated("2", "4", Status::Success);
    check(session.campusAddresses().isEmpty(), "Old generation choice survived a new session");
    reply(engine, "3", "192.168.4.19");
    until([&] { return reads == 4; });
    engine.stop();
    reply(engine, "3", "192.168.4.19");
    resume.release();
    until([&] { return !session.isBusy(); });
    check(session.model().isEmpty() && session.status() == Status::Stale, "Stopped session accepted late facts");

    Engine invalid;
    std::atomic_bool unsupportedName = false;
    NetworkPolicySession malformed(&invalid, [&] {
        if (unsupportedName) return DnsSnapshot{{}, {{"nrpt", QJsonArray{QJsonObject{{"Namespace", QJsonArray{QStringLiteral("\u6821\u56ed")}}}}}}};
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
    unsupportedName = true;
    check(malformed.refresh(), "Unrepresentable namespace cannot be refreshed");
    reply(invalid, "1", "192.168.1.19");
    until([&] { return !malformed.isBusy(); });
    check(malformed.status()==Status::Failed && malformed.model().isEmpty() && invalid.policies.isEmpty(),
          "Readable but unrepresentable DNS published partial facts or changed the active policy");
    invalid.unsupported = true;
    check(malformed.refresh(), "Capability failure cannot be refreshed");
    until([&] { return !malformed.isBusy(); });
    check(malformed.status() == Status::Unavailable && malformed.model().isEmpty(), "Missing capability misreported");

    Engine recoveryEngine;
    std::atomic_bool failedDns = false;
    QSemaphore recoveryEntered, recoveryResume;
    NetworkPolicySession recovery(&recoveryEngine, [&] {
        if (!failedDns) return DnsSnapshot{};
        recoveryEntered.release();
        check(recoveryResume.tryAcquire(1, 2000), "Release failed recovery DNS fixture");
        return DnsSnapshot{{PlatformOperationResult::Status::TimedOut, {}}, {}};
    });
    emit recoveryEngine.sessionStarted("6");
    auto recoveryInitial = initialPolicy;
    recoveryInitial["generation"] = "6";
    emit recoveryEngine.initialProtectionApplied(recoveryInitial);
    reply(recoveryEngine, "6", "192.168.7.19");
    until([&] { return !recovery.isBusy(); });
    check(recovery.setCampusAddress("192.168.7.20", true), "Recovery fixture could not choose campus");
    const auto confirmedPolicy = recoveryEngine.policies.last();
    emit recoveryEngine.policyUpdated("6", "1", Status::Success);
    failedDns = true;
    check(recovery.refresh(), "Recovery fixture could not refresh");
    reply(recoveryEngine, "6", "192.168.8.19");
    until([&] { return recoveryEntered.available() != 0; });
    check(recovery.status() == Status::Pending && !recovery.setCampusAddress("192.168.8.20", true),
          "Failed refresh allowed a new unverified campus exception");
    check(recovery.setCampusAddress("192.168.7.20", false), "Failed DNS refresh prevented removing an owned campus choice");
    const auto restoration = recoveryEngine.policies.last();
    check(restoration["protected"] == confirmedPolicy["protected"] && restoration["schema_version"] == confirmedPolicy["schema_version"]
          && restoration["protected_names"] == confirmedPolicy["protected_names"]
          && restoration["protected_names"].toArray() == initialNames
          && restoration["campus_names"] == confirmedPolicy["campus_names"]
          && restoration["generation"] == "6" && restoration["revision"] == "2" && restoration["campus"].toArray().isEmpty(),
          "Recovery guessed new scopes or discarded the last confirmed policy identity");
    emit recoveryEngine.policyUpdated("6", "2", Status::Failed);
    check(recovery.campusAddresses() == QJsonArray{"192.168.7.20"} && !recovery.isPolicyUpdating() && recovery.isBusy(),
          "Failed recovery discarded the effective exception or confused the remaining native read");
    recoveryResume.release();
    until([&] { return !recovery.isBusy(); });
    check(recovery.status() == Status::Failed && recovery.setCampusAddress("192.168.7.20", false),
          "Failed DNS refresh prevented retrying owned recovery");
    check(recoveryEngine.policies.last()["revision"] == "3", "Recovery retry reused its failed revision");
    emit recoveryEngine.policyUpdated("6", "3", Status::Success);
    check(recovery.campusAddresses().isEmpty() && recovery.status() == Status::Failed,
          "Recovery either retained the exception or misreported failed inspection as successful");

    Engine nameEngine;
    std::atomic_bool nameDnsFails = false;
    NetworkPolicySession nameSession(&nameEngine, [&] {
        return nameDnsFails ? DnsSnapshot{{PlatformOperationResult::Status::TimedOut, {}}, {}} : DnsSnapshot{};
    });
    emit nameEngine.sessionStarted("7");
    auto nameInitial = initialPolicy;
    nameInitial["generation"] = "7";
    emit nameEngine.initialProtectionApplied(nameInitial);
    reply(nameEngine, "7", "192.168.9.19");
    until([&] { return !nameSession.isBusy(); });
    check(nameSession.setCampusAddress("192.168.9.20", true), "Name fixture could not choose its address");
    emit nameEngine.policyUpdated("7", "1", Status::Success);
    for (const auto &bad : {".", "*.confirmed.native.test", "127.0.0.1", "bad..test"})
        check(!nameSession.setCampusName(bad, true), "Malformed name choice was submitted");
    check(nameEngine.policies.size()==1 && nameSession.setCampusName("HOST.Confirmed.Native.Test.", true)
          && nameSession.campusNames().isEmpty() && !nameSession.setCampusAddress("192.168.9.21",true),
          "Invalid or unconfirmed name published, or policy writes overlapped");
    auto chosenNamePolicy = nameEngine.policies.last();
    check(chosenNamePolicy["revision"]=="2" && chosenNamePolicy["protected_names"].toArray()==initialNames
          && chosenNamePolicy["campus_names"].toArray()==QJsonArray{"host.confirmed.native.test"}
          && chosenNamePolicy["campus"].toArray()==QJsonArray{"192.168.9.20"},
          "Name update replaced confirmed address choices or expanded its concrete scope");
    emit nameEngine.policyUpdated("6", "2", Status::Success);
    check(nameSession.isPolicyUpdating() && nameSession.campusNames().isEmpty(), "Foreign name confirmation applied");
    emit nameEngine.policyUpdated("7", "2", Status::Invalid);
    check(nameSession.campusNames().isEmpty() && nameSession.campusAddresses()==QJsonArray{"192.168.9.20"},
          "Invalid name update damaged the last effective full policy");
    check(nameSession.setCampusName("host.confirmed.native.test", true), "Valid name retry rejected");
    emit nameEngine.policyUpdated("7", "3", Status::Success);
    check(nameSession.campusNames()==QJsonArray{"host.confirmed.native.test"}
          && nameSession.setCampusName("HOST.confirmed.native.test.", true) && nameEngine.policies.size()==3,
          "Confirmed concrete name was lost or repeated normalization wrote another policy");
    check(nameSession.setCampusAddress("192.168.9.21", true)
          && nameEngine.policies.last()["campus_names"].toArray()==nameSession.campusNames(),
          "Address update cleared a confirmed name exception");
    emit nameEngine.policyUpdated("7", "4", Status::Success);
    chosenNamePolicy = nameEngine.policies.last();
    nameDnsFails = true;
    check(nameSession.refresh(), "Name recovery refresh failed");
    reply(nameEngine, "7", "192.168.10.19");
    until([&] { return !nameSession.isBusy(); });
    check(nameSession.status()==Status::Failed && !nameSession.setCampusName("new.confirmed.native.test",true)
          && nameSession.setCampusName("host.confirmed.native.test",false),
          "Failed inspection enabled a new exception or prevented owned name recovery");
    auto nameRecovery = nameEngine.policies.last();
    check(nameRecovery["protected"]==chosenNamePolicy["protected"] && nameRecovery["campus"]==chosenNamePolicy["campus"]
          && nameRecovery["protected_names"]==chosenNamePolicy["protected_names"] && nameRecovery["campus_names"].toArray().isEmpty(),
          "Name recovery guessed refreshed scopes or discarded unrelated address state");
    emit nameEngine.policyUpdated("7", "5", Status::Failed);
    check(!nameSession.campusNames().isEmpty() && nameSession.setCampusName("host.confirmed.native.test",false),
          "Failed recovery lost the effective name exception or prevented retry");
    emit nameEngine.policyUpdated("7", "6", Status::Success);
    check(nameSession.campusNames().isEmpty() && nameSession.campusAddresses()==QJsonArray({"192.168.9.20","192.168.9.21"})
          && nameSession.status()==Status::Failed, "Name recovery changed unrelated choices or invented successful inspection");
    emit nameEngine.sessionStarted("8");
    emit nameEngine.policyUpdated("7", "3", Status::Success);
    check(nameSession.campusNames().isEmpty() && nameSession.campusAddresses().isEmpty(), "New generation inherited old name policy");

    Engine unsignedEngine;
    NetworkPolicySession unsignedModel(&unsignedEngine, [] { return DnsSnapshot{}; });
    emit unsignedEngine.sessionStarted("4");
    auto unsignedNetwork = network("192.168.5.19");
    unsignedNetwork.remove("schema_version");
    emit unsignedEngine.snapshotReady(Kind::Network, "4", unsignedNetwork, Status::Success);
    emit unsignedEngine.connectionEstablished();
    emit unsignedEngine.snapshotReady(Kind::Resources, "4", resources("192.168.5.19"), Status::Success);
    until([&] { return !unsignedModel.isBusy(); });
    check(unsignedModel.status() == Status::Success && !unsignedModel.setCampusAddress("192.168.5.20", true)
          && unsignedModel.policyStatus() == Status::Unavailable && unsignedEngine.policies.isEmpty(),
          "Unversioned inspection invented a policy schema");

    Engine stoppedPolicy;
    NetworkPolicySession stoppingPolicy(&stoppedPolicy, [] { return DnsSnapshot{}; });
    emit stoppedPolicy.sessionStarted("5");
    reply(stoppedPolicy, "5", "192.168.6.19");
    until([&] { return !stoppingPolicy.isBusy(); });
    check(stoppingPolicy.setCampusAddress("192.168.6.20", true), "Pending stop fixture could not write");
    stoppedPolicy.stop();
    emit stoppedPolicy.policyUpdated("5", "1", Status::Success);
    check(stoppingPolicy.status() == Status::Stale && stoppingPolicy.campusAddresses().isEmpty() && !stoppingPolicy.isBusy(),
          "Stopped model accepted a late policy acknowledgement");

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
