#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "infrastructure/dns/dnsroutepublisher.h"
#include "infrastructure/networkaccess/linux/networkaccess.h"
#include "application/networkprotection.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QStandardPaths>
#include "tests/platform/networkhelperfixture.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QSaveFile>
#include <QThread>
#include <QTimer>
#include <QTcpServer>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <future>

using ProxyCheck::check;

template<class Predicate> static void until(Predicate done) {
    QElapsedTimer timer;
    timer.start();
    while (!done() && timer.elapsed() < 10000) QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    check(done(), "Qt TUN operation completed within deadline");
}
static int tunReferences() {
    int count = 0;
    for (const auto &entry : QDir("/proc/self/fd").entryList(QDir::Files | QDir::System)) {
        char target[256];
        const auto path = QString("/proc/self/fd/") + entry;
        const auto size = ::readlink(path.toLocal8Bit().constData(), target, sizeof(target));
        if (size > 0 && QByteArray(target, size) == "/dev/net/tun") ++count;
    }
    return count;
}
static QStringList systemAddresses(const char *hostname, int family = AF_INET) {
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *answer = nullptr;
    const int status = ::getaddrinfo(hostname, nullptr, &hints, &answer);
    if (status) std::cerr << "system DNS " << hostname << ": " << ::gai_strerror(status) << " (" << status << ")\n";
    check(status == 0 && answer, "ordinary system DNS lookup succeeded");
    QStringList addresses;
    for (auto *entry = answer; entry; entry = entry->ai_next) {
        char numeric[NI_MAXHOST];
        check(::getnameinfo(entry->ai_addr, entry->ai_addrlen, numeric, sizeof(numeric), nullptr, 0, NI_NUMERICHOST) == 0,
              "system DNS returned a numeric address");
        addresses.append(QString::fromLatin1(numeric));
    }
    ::freeaddrinfo(answer);
    return addresses;
}
static int exerciseApplicationNetworkAccess(const ConnectionProfile &profile)
{
    auto *engine = new EmbeddedCoreEngine;
    NetworkPolicySession policy(engine, readSystemDnsSnapshot);
    auto *network = new LinuxNetworkAccess(engine, &policy,
        EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt());
    ConnectionSession session(engine, nullptr, network);
    QObject::connect(&session, &ConnectionSession::diagnostic, [](const QString &message) { std::cerr << message.toStdString() << '\n'; });
    QObject::connect(&session, &ConnectionSession::authenticationRequired, [engine](const QJsonObject &request) {
        engine->respond(CoreEngine::responseFor(request, {{"action", "submit"}, {"code", "fixture-code"}}));
    });
    QJsonObject initialPolicy, lastNativeNetwork;
    QObject::connect(engine, &CoreEngine::initialProtectionApplied, [&](const QJsonObject &value) { initialPolicy = value; });
    QObject::connect(engine, &CoreEngine::snapshotReady, [&](CoreEngine::Snapshot kind, const QString &, const QJsonObject &value, CoreEngine::RequestStatus status) {
        if (kind == CoreEngine::Snapshot::Network && status == CoreEngine::RequestStatus::Success) lastNativeNetwork = value;
    });
    const auto originalView = [&](const QUuid &owner) {
        until([&] { return !policy.isBusy(); });
        const auto model = policy.model();
        const auto protection = protectionConfiguration(model["targets"].toArray(), model["name_targets"].toArray());
        bool rulesOriginal = true;
        for (const auto &value : model["network"].toObject()["policy_rules"].toArray())
            rulesOriginal &= value.toObject()["table"].toInteger() != linuxSourceTable(owner);
        const bool matches = rulesOriginal && policy.status() == CoreEngine::RequestStatus::Success
            && protection["protected"] == initialPolicy["protected"] && protection["protected_names"] == initialPolicy["protected_names"];
        if (!matches) std::cerr << QJsonDocument(QJsonObject{{"initial", initialPolicy}, {"view", protection}, {"model", model},
            {"raw_network", lastNativeNetwork}}).toJson(QJsonDocument::Compact).toStdString() << '\n';
        check(matches, "owned routes and DNS never become original protection scopes");
    };
    const bool withdrawalCrash = qgetenv("JC_NATIVE_NETWORK_WITHDRAW_CRASH") == "1";
    const bool automaticExit = qgetenv("JC_NATIVE_NETWORK_AUTORESTART") == "1";
    const bool exitChange = qgetenv("JC_NATIVE_NETWORK_EXIT_CHANGE") == "1";
    const bool helperLoss = qgetenv("JC_NATIVE_NETWORK_HELPER_LOSS") == "1" || withdrawalCrash;
    int coreFinished = 0;
    QObject::connect(engine,&CoreEngine::finished,[&] { ++coreFinished; });
    int started = 0, finished = 0;
    bool sawPreparing = false;
    QObject::connect(engine, &CoreEngine::sessionStarted, [&] { ++started; });
    QObject::connect(&session, &ConnectionSession::finished, [&](ConnectionError error) {
        const auto expected = helperLoss && finished == 0 ? ConnectionError::OTHER
            : exitChange && !automaticExit && finished == 0 ? ConnectionError::NETWORK_FAILED : ConnectionError::NONE;
        check(error == expected, "application network lifecycle retains its actual failure result"); ++finished;
    });
    QObject::connect(&session, &ConnectionSession::progressChanged, [&] {
        sawPreparing |= session.phase() == ConnectionPhase::NetworkPreparing;
    });
    QString hintPath;
    QByteArray previousOwner;
    const QDir hints(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/network-owners");
    for (int round = 0; round < 2; ++round) {
        if (round && !automaticExit) {
            // Reproduce a crash between the durable UUID hint and the first privileged write.
            QSaveFile hint(hintPath);
            check(hint.open(QIODevice::WriteOnly) && hint.write(previousOwner) == previousOwner.size() && hint.commit(),
                  "seed an absent privileged owner for startup recovery");
        }
        if (!round || !automaticExit)
            check(session.start(profile, {automaticExit,1000}), "start application connection");
        until([&] { return session.state() == ConnectionState::Running || !session.isActive(); });
        const int references=tunReferences();
        const bool ready=session.state() == ConnectionState::Running && session.phase() == ConnectionPhase::CampusReady
              && sawPreparing && started == round + 1 && references == 2;
        if(!ready)std::cerr<<"network readiness round="<<round<<" state="<<int(session.state())<<" phase="<<int(session.phase())
            <<" preparing="<<sawPreparing<<" starts="<<started<<" TUN references="<<references<<'\n';
        check(ready,"application confirms network ownership and core attachment before campus readiness");
        if (automaticExit && round) {
            check(session.reconnectAttempt() == 1,"Changed exit reused the existing reconnect budget");
            until([&] { return !policy.isBusy(); });
            bool changedGateway = false;
            for (const auto &value : policy.model()["network"].toObject()["routes"].toArray()) {
                const auto row = value.toObject();
                changedGateway |= row["destination"] == "0.0.0.0/0" && row["gateway"] == "192.0.2.2";
            }
            check(changedGateway,"Automatic restart adopted the actual changed original exit");
        }
        const auto files = hints.entryList({"*.owner"}, QDir::Files);
        check(files.size() == 1, "one durable network responsibility hint");
        hintPath = hints.filePath(files.first());
        QFile hint(hintPath);
        check(hint.open(QIODevice::ReadOnly), "read current connection responsibility");
        const auto owner = hint.readAll();
        check(!QUuid(owner).isNull() && owner != previousOwner, "fresh root ownership for each attempt");
        previousOwner = owner;
        originalView(QUuid(owner));
        check(policy.refresh(), "explicit original-network refresh remains available during takeover");
        originalView(QUuid(owner));
        const auto activeGeneration = policy.currentGeneration();
        const auto publish = [&](const QString &suffix) {
            QSaveFile marker(QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY"))+suffix);
            const auto bytes = QJsonDocument(QJsonObject{{"pid",QCoreApplication::applicationPid()},
                {"owner",QString::fromLatin1(owner)},{"generation",activeGeneration}}).toJson(QJsonDocument::Compact);
            check(marker.open(QIODevice::WriteOnly) && marker.write(bytes) == bytes.size() && marker.commit(),
                  "publish the application's active helper for isolated network changes");
        };
        const bool choose = qgetenv("JC_NATIVE_NETWORK_CHOICES") == "1";
        const bool originalDNS = qgetenv("JC_NATIVE_NETWORK_ORIGINAL_DNS") == "1";
        const auto chooseAddress = [&](const QString &address, bool campus) {
            check(policy.setCampusAddress(address,campus),"submit a running campus/original address choice");
            until([&] { return !policy.isBusy() || !session.isActive(); });
            check(session.state() == ConnectionState::Running && policy.policyStatus() == CoreEngine::RequestStatus::Success
                  && policy.campusAddresses().contains(address) == campus,"campus choice waits for core and actual helper routing confirmation");
            originalView(QUuid(owner));
        };
        const bool originalPeer = choose && qgetenv("JC_NATIVE_ORIGINAL_PEER") == "1";
        if (originalPeer) exerciseOriginalNetworkTraffic();
        if (choose) for (const auto *address : {"198.18.0.6","198.18.0.7"}) chooseAddress(QString::fromLatin1(address),true);
        const auto chooseName = [&](bool campus) {
            check(policy.setCampusName("campus.test",campus),"submit the overlapping native DNS name choice");
            until([&] { return !policy.isBusy() || !session.isActive(); });
            const bool confirmed = session.state() == ConnectionState::Running && policy.policyStatus() == CoreEngine::RequestStatus::Success
                && policy.campusNames().contains("campus.test") == campus;
            if (!confirmed) std::cerr << "name choice campus=" << campus << " state=" << int(session.state())
                << " model=" << int(policy.status()) << " policy=" << (policy.policyStatus() ? int(*policy.policyStatus()) : -1)
                << " busy=" << policy.isBusy() << '\n';
            check(confirmed,"name choice waits for core and native capture confirmation");
        };
        const auto originalLookup = [&](const QString &hostname) {
            auto lookup = std::async(std::launch::async, [hostname] { return systemAddresses(hostname.toUtf8().constData()); });
            until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
            check(lookup.get() == QStringList{"198.18.0.7"},"overlapping original DNS kept its native server answer");
            const auto route = runPlatformCommand(trustedIpRouteUtility(),{"-N","-j","-4","route","get","198.18.0.7"});
            const auto rows = QJsonDocument::fromJson(route.output.toUtf8()).array();
            check(route.result.succeeded() && rows.size() == 1 && rows[0].toObject()["dev"] == "helperorig0",
                "original DNS released capture and its temporary source pin before returning the answer");
            exerciseOriginalNetworkTraffic(QHostAddress("198.18.0.7"),QHostAddress("198.18.0.5"));
        };
        if (originalDNS) chooseName(true);
        auto lookup = std::async(std::launch::async, [] { return systemAddresses("campus.test"); });
        until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
        const auto addresses = lookup.get();
        check(addresses.size() == 1, "application publishes campus DNS through the owned helper");
        originalView(QUuid(owner));
        exerciseNativeTUNTraffic(QHostAddress(addresses.first()));
        exerciseNativeSSH(QHostAddress(addresses.first()));
        if (originalPeer) exerciseNonCampusNetworkTraffic();
        if (qgetenv("JC_NATIVE_NETWORK_OBSERVE") == "1" && round == 0) {
            publish({});
            until([&] { return !session.isActive() || (!policy.isBusy()
                && policy.confirmedProtection()["protected"].toArray().contains("198.18.0.6/32")); });
            check(session.state() == ConnectionState::Running,"Overlay addition updated protection without losing campus readiness");
            exerciseOriginalNetworkUDP();
            publish(".protected");
            until([&] { return !session.isActive() || (!policy.isBusy()
                && !policy.confirmedProtection()["protected"].toArray().contains("198.18.0.6/32")); });
            check(session.state() == ConnectionState::Running,"Overlay removal settled both policy and capture ownership");
            exerciseNativeTUNUDP();
            std::cout << "PASS: automatic overlay protection and withdrawal route actual UDP to original then campus, including empty datagrams\n";
        }
        if (exitChange && round == 0) {
            QMetaObject::Connection barrier;
            if (automaticExit) {
                barrier = QObject::connect(&session,&ConnectionSession::reconnectScheduled,&session,[&](int) {
                    check(!finished && tunReferences() == 0 && !QFileInfo::exists(hintPath)
                          && session.state() == ConnectionState::Reconnecting,"Restart is scheduled only after root ownership and core fd release");
                    publish(".restored");
                    const auto proceed = QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY")) + ".continue";
                    until([&] { return QFileInfo::exists(proceed); });
                });
            }
            publish({});
            until([&] { return session.state() == ConnectionState::Reconnecting || !session.isActive(); });
            if (automaticExit) {
                QObject::disconnect(barrier);
                check(session.state() == ConnectionState::Reconnecting,"Changed exit retained the requested automatic restart");
            } else {
                check(finished == 1 && tunReferences() == 0 && !QFileInfo::exists(hintPath)
                      && session.state() == ConnectionState::Failed,"Disabled automatic restart restores ownership and ends the connection");
                publish(".restored");
                const auto proceed = QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY")) + ".continue";
                until([&] { return QFileInfo::exists(proceed); });
            }
            continue;
        }
        if (originalDNS) {
            originalLookup(QString("private-%1.campus.test").arg(round));
            chooseName(false);
            originalLookup(QString("withdrawn-%1.campus.test").arg(round));
        }
        if (choose && !(withdrawalCrash && round == 0)) for (const auto *address : {"198.18.0.6","198.18.0.7"}) {
            chooseAddress(QString::fromLatin1(address),false);
            const auto selected = runPlatformCommand(trustedIpRouteUtility(),{"-N","-j","-4","route","get",QString::fromLatin1(address)});
            const auto rows = QJsonDocument::fromJson(selected.output.toUtf8()).array();
            check(selected.result.succeeded() && rows.size() == 1 && rows[0].toObject()["dev"] == "helperorig0",
                  "revoked campus choice restores the kernel's actual original route");
        }
        if (originalPeer && !(withdrawalCrash && round == 0)) exerciseOriginalNetworkTraffic();
        if (helperLoss && round == 0) {
            publish({});
            if (withdrawalCrash) {
                const auto proceed = QString::fromLocal8Bit(qgetenv("JC_NATIVE_TUN_READY")) + ".continue";
                until([&] { return QFileInfo::exists(proceed); });
                check(policy.setCampusAddress("198.18.0.6",false),"start live route withdrawal after the external checkpoint observer attaches");
            }
            until([&] { return coreFinished == 1 && tunReferences() == 0; });
            check(session.isActive() && session.state() == ConnectionState::Stopping
                  && session.phase() == ConnectionPhase::NetworkRestoring && QFileInfo::exists(hintPath)
                  && !session.start(profile,{}),"helper loss releases the device but keeps unresolved responsibility and blocks restart");
            session.stop();
        }
        if (choose && round == 0 && !helperLoss)
            check(policy.setCampusAddress("198.18.0.6",true) && policy.isPolicyUpdating(),
                  "prepare a policy transaction cancelled before core application");
        session.stop();session.stop();
        until([&] { return !session.isActive(); });
        check(finished == (automaticExit ? 1 : round + 1) && tunReferences() == 0 && !QFileInfo::exists(hintPath),
              "application restores owned network before releasing the core and responsibility hint");
    }
    if (qgetenv("JC_NATIVE_NETWORK_ORIGINAL_DNS") == "1") std::cout << "PASS: automatic original DNS source preparation, actual endpoint replacement, shared-IP exclusion and name choice withdrawal\n";
    if (automaticExit) std::cout << "PASS: changed exit resumes automatically after confirmed restoration with a fresh owner and the changed gateway\n";
    if (exitChange) std::cout << "PASS: changed original exit automatically restores ownership and restarts with a fresh owner\n";
    if (withdrawalCrash) std::cout << "PASS: application capture withdrawal checkpoint crash restores DNS/routes and restarts with a fresh owner\n";
    if (helperLoss) std::cout << "PASS: application helper loss releases core/device before explicit recovery and fresh restart\n";
    std::cout << "PASS: ordinary native TCP/UDP via application network startup recovery, campus readiness, original network views, live address choices, DNS and ordered stop/restart\n";
    return 0;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    check(argc == 3 && QByteArray(argv[1]) == "--tun-gateway", "requires native gateway fixture");
    check(::getuid() != 0 && ::getuid() == ::geteuid(), "Qt data plane stays unprivileged");
    const QUuid firstOwner(QString::fromUtf8(qgetenv("JC_NATIVE_TUN_HELPER_OWNER")));
    check(!firstOwner.isNull(), "requires an isolated installed-helper owner");
    const auto config = QJsonDocument::fromJson(argv[2]).object();
    const auto server = config["server"].toObject(), auth = config["auth"].toObject();
    ConnectionProfile profile;
    profile.endpoint.server = server["host"].toString();
    profile.endpoint.port = server["port"].toInt();
    profile.endpoint.authType = auth["method"].toString().mid(QStringLiteral("auth/").size());
    profile.endpoint.phone = auth["phone"].toString();
    profile.endpoint.loginDomain = auth["domain"].toString();
    profile.tls.caPem = config["tls"].toObject()["ca_pem"].toString();
    profile.keepAlive.mode = "off";
    if (qgetenv("JC_NATIVE_NETWORK_SESSION") == "1") return exerciseApplicationNetworkAccess(profile);
    auto engine = std::make_unique<EmbeddedCoreEngine>();
    LinuxNetworkHelperClient helper;
    DNSRoutePublisher<LinuxNetworkHelperClient> publisher(engine.get(), &helper, nullptr, {},
        [&helper](const QStringList &addresses) -> std::optional<QStringList> {
            const auto owned = helper.ownedConfiguration();
            return owned ? excludeCampusCaptureAddresses(owned->capturePrefixes, addresses) : std::nullopt;
        });
    QList<PlatformOperationResult> helperReplies;
    QList<PlatformOperationResult> helperLosses;
    QObject::connect(&helper, &LinuxNetworkHelperClient::finished, [&](LinuxNetworkHelperClient::Operation, PlatformOperationResult result) {
        helperReplies.append(result);
    });
    QObject::connect(&helper, &LinuxNetworkHelperClient::ownershipLost, [&](PlatformOperationResult result) { helperLosses.append(result); });
    QString generation;
    int ready = 0, finished = 0;
    int resourceReplies = 0, networkReplies = 0;
    QJsonObject resources, confirmedPolicy, network;
    QList<CoreEngine::RequestStatus> replies;
    QObject::connect(engine.get(), &CoreEngine::sessionStarted, [&](const QString &value) { generation = value; });
    QObject::connect(engine.get(), &CoreEngine::authenticationRequired, [&](const QJsonObject &request) {
        engine->respond(CoreEngine::responseFor(request, {{"action", "submit"}, {"code", "fixture-code"}}));
    });
    QObject::connect(engine.get(), &CoreEngine::initialProtectionApplied, [&](const QJsonObject &policy) {
        check(policy["generation"] == generation, "capture plan uses the confirmed session protection");
        confirmedPolicy = policy;
    });
    QObject::connect(engine.get(), &CoreEngine::connectionEstablished, [&] { ++ready; });
    QObject::connect(engine.get(), &CoreEngine::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "Qt TUN shutdown succeeds"); ++finished;
    });
    QObject::connect(engine.get(), &CoreEngine::tunAttached, [&](const QString &value, CoreEngine::RequestStatus status) {
        check(QThread::currentThread() == app.thread() && value == generation, "TUN reply preserves GUI thread and generation");
        replies.append(status);
    });
    QObject::connect(engine.get(), &CoreEngine::snapshotReady,
        [&](CoreEngine::Snapshot kind, const QString &value, const QJsonObject &snapshot, CoreEngine::RequestStatus status) {
            if (value != generation) return;
            check(status == CoreEngine::RequestStatus::Success,"read actual preparation snapshot");
            if (kind == CoreEngine::Snapshot::Resources) { resources = snapshot["resources"].toObject(); ++resourceReplies; }
            else { network = snapshot["network"].toObject(); ++networkReplies; }
        });
    for (int round = 0; round < 2; ++round) {
        check(tunReferences() == 0, "previous session released every Qt/core TUN reference");
        check(engine->start(profile, CoreEngine::Operation::Connect), "start ordinary Qt core session");
        until([&] { return ready == round + 1; });
        const bool systemDNS = qgetenv("JC_NATIVE_TUN_DNS") == "1";
        QStringList prefixes{"198.18.0.6/32"};
        const auto coreMTU = EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt();
        auto configuration = helperFixtureConfiguration(prefixes,coreMTU);
        QHostAddress tcpTarget("198.18.0.6");
        if (systemDNS) {
            const auto previous = resourceReplies, previousNetwork = networkReplies;
            engine->readSnapshot(CoreEngine::Snapshot::Resources,generation);
            engine->readSnapshot(CoreEngine::Snapshot::Network,generation);
            until([&] { return resourceReplies > previous && networkReplies > previousNetwork; });
            const auto dns = resources["campus_dns"].toString();
            check(resources["campus_dns_enabled"].toBool() && QHostAddress(dns).protocol() == QAbstractSocket::IPv4Protocol,
                  "dynamic route fixture uses the school's actual authorized DNS server");
            auto worker = std::async(std::launch::async, [resources,confirmedPolicy,network,coreMTU] {
                return prepareLinuxNetworkHelper(resources,confirmedPolicy,network,readSystemDnsSnapshot(),{},coreMTU);
            });
            until([&] { return worker.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
            const auto preparation = worker.get();
            check(preparation.result.succeeded(),qPrintable(preparation.result.detail));
            configuration = preparation.configuration;
            prefixes = configuration.capturePrefixes;
            check(configuration.originalInterface == "helperorig0" && configuration.originalSource == "192.0.2.1"
                  && configuration.address != configuration.peer && !configuration.dnsDomains.isEmpty(),
                  "actual kernel exit and collision-free device addresses feed the installed helper");
        }
        const auto owner = round == 0 ? firstOwner : QUuid::createUuid();
        auto helperPrevious = helperReplies.size();
        helper.apply(owner, configuration);
        until([&] { return helperReplies.size() > helperPrevious; });
        check(helperReplies.last().succeeded(), qPrintable(helperReplies.last().detail));
        check(helper.state() == LinuxNetworkHelperClient::State::Active, "installed helper delivered its owned device");
        const quint32 mtu = configuration.mtu;
        const int borrowed = helper.descriptor();
        const int descriptor = ::fcntl(borrowed, F_DUPFD_CLOEXEC, 3);
        const int flags = ::fcntl(descriptor, F_GETFL);
        check(flags >= 0 && (flags & O_NONBLOCK) && tunReferences() > 0, "received nonblocking native TUN reference");
        const auto attach = [&](quint32 value) {
            const auto previous = replies.size();
            engine->attachTUN(generation, descriptor, value, systemDNS);
            until([&] { return replies.size() > previous; });
        };
        attach(mtu + 1);
        check(replies.last() == CoreEngine::RequestStatus::Invalid, "Qt preserves kernel MTU rejection");
        check(::fcntl(descriptor, F_GETFL) == flags, "failed handoff preserves caller descriptor and flags");
        const auto previous = replies.size();
        engine->attachTUN(generation, descriptor, mtu, systemDNS);
        ::close(descriptor);
        until([&] { return replies.size() > previous; });
        check(replies.last() == CoreEngine::RequestStatus::Success, "queued fd remains valid after caller closes its reference");
        if (systemDNS) {
            const auto references = tunReferences();
            helperPrevious = helperReplies.size();
            auto lookup = std::async(std::launch::async, [] { return systemAddresses("campus.test"); });
            until([&] { return lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready; });
            const auto addresses = lookup.get();
            check(!addresses.isEmpty(), "system DNS returned a campus address");
            for (const auto &address : addresses) {
                for (const auto &prefix : prefixes)
                    check(!QHostAddress(address).isInSubnet(QHostAddress::parseSubnet(prefix)),
                          "DNS-discovered TCP address was not already part of initial IP capture");
            }
            tcpTarget = QHostAddress(addresses.first());
            check(helperReplies.size() > helperPrevious && helperReplies.last().succeeded()
                  && helper.state() == LinuxNetworkHelperClient::State::Active
                  && helper.descriptor() == borrowed && tunReferences() == references,
                  "DNS reply waits for automatic route publication without changing fd ownership");
            std::cout << "PASS: DNS reply waits for owned capture routes before ordinary TCP\n" << std::flush;
            for (const auto *hostname : {"public.test", "host.original.test"}) {
                for (const auto &address : systemAddresses(hostname))
                    check(address == "203.0.113.9", "public and original names retain their original DNS path");
                for (const auto &address : systemAddresses(hostname, AF_INET6))
                    check(address == "2001:db8::9", "original IPv6 DNS answers remain available");
            }
            for (const auto &address : systemAddresses("localhost", AF_UNSPEC))
                check(QHostAddress(address).isLoopback(), "localhost remains on the local computer");
            QTcpServer localServer;
            check(localServer.listen(QHostAddress::LocalHost), "open an ordinary local TCP listener");
            QTcpSocket localClient;
            localClient.connectToHost("localhost", localServer.serverPort());
            check(localClient.waitForConnected(5000) && localClient.peerAddress().isLoopback(),
                  "localhost TCP still reaches this computer during campus DNS takeover");
            std::cout << "PASS: ordinary getaddrinfo through installed helper and core TUN DNS\n" << std::flush;
        }
        exerciseNativeTUNTraffic(tcpTarget);
        bool helperLost = false;
        if (const auto path = qgetenv("JC_NATIVE_TUN_READY"); round == 0 && !path.isEmpty()) {
            check(tunReferences() >= 2, "helper client and core retain the active native device");
            QSaveFile marker(QString::fromLocal8Bit(path));
            const auto data = QJsonDocument(QJsonObject{{"pid", QCoreApplication::applicationPid()},
                {"owner", owner.toString(QUuid::WithoutBraces)}, {"generation", generation}}).toJson(QJsonDocument::Compact);
            check(marker.open(QIODevice::WriteOnly) && marker.write(data) == data.size() && marker.commit(),
                  "publish active core/helper state for the isolated crash fixture");
            if (qgetenv("JC_NATIVE_TUN_SCENARIO") == "helper-loss") {
                until([&] { return !helperLosses.isEmpty(); });
                check(helperLosses.size() == 1 && !helperLosses[0].succeeded() && helperLosses[0].mayHaveChanged
                    && helper.state() == LinuxNetworkHelperClient::State::RecoveryRequired && helper.descriptor() == -1
                    && tunReferences() == 1, "helper loss revokes the client fd while core still owns its reference");
                helperLost = true;
            } else {
                QTimer::singleShot(30000, &app, [] { check(false, "managed native TUN fixture was not stopped"); });
                app.exec();
                return 1;
            }
        }
        // Queue another owned reference immediately before stop/destruction.
        if (!helperLost) {
            const int retained = ::fcntl(helper.descriptor(), F_DUPFD_CLOEXEC, 3);
            check(retained >= 0, "retain helper-owned fd before queued stop");
            engine->attachTUN(generation, retained, mtu);
            ::close(retained);
        }
        if (round == 0) {
            engine->stop();
            until([&] { return finished == 1; });
            if (!helperLost) {
                until([&] { return replies.size() == previous + 2; });
                check(replies.last() == CoreEngine::RequestStatus::Stale, "queued reply becomes stale during stop");
            }
        } else engine.reset();
        check(tunReferences() == (helperLost ? 0 : 1), "core releases active and queued references before helper restore");
        helperPrevious = helperReplies.size();
        helper.restore();
        until([&] { return helperReplies.size() > helperPrevious; });
        check(helperReplies.last().succeeded() && helper.state() == LinuxNetworkHelperClient::State::Idle
              && tunReferences() == 0, "helper restore releases its descriptor, network state and receipt");
    }
    std::cout << "PASS: ordinary native TCP/UDP via installed helper, queued Qt fd handoff, stop, restart and destruction\n";
}
