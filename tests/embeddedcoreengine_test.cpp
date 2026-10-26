#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "justconnect.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QList>
#include <QTimer>
#include <QJsonDocument>
#include <QTcpSocket>
#include <QTcpServer>
#include <QUdpSocket>
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#elif defined(Q_OS_WIN)
#include <windows.h>
#endif
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
#if (defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_WIN)) && !defined(ABI_FIXTURE)
static void rejectedDeviceHandoffReleasesItsBorrowedHandle(const ConnectionProfile &profile) {
    EmbeddedCoreEngine engine;int finished=0,replies=0;
#ifdef Q_OS_WIN
    HANDLE reading=nullptr;
#else
    int reading=-1;
#endif
    QObject::connect(&engine,&CoreEngine::finished,[&]{++finished;});
    QObject::connect(&engine,&CoreEngine::tunAttached,[&](const QString &value,CoreEngine::RequestStatus status){
        check(value=="0" && status!=CoreEngine::RequestStatus::Success,"invalid-generation device handoff is rejected");
#ifdef Q_OS_WIN
        DWORD available=0;
        const bool released=!::PeekNamedPipe(reading,nullptr,0,nullptr,&available,nullptr) && ::GetLastError()==ERROR_BROKEN_PIPE;
#else
        char byte=0;errno=0;const auto size=::read(reading,&byte,1);
        if(size!=0)std::cerr<<"borrowed descriptor reply="<<replies<<" read="<<size<<" errno="<<errno<<'\n';
        const bool released=size==0;
#endif
        check(released,"device rejection publishes only after the borrowed handle closes");++replies;
    });
    for(int attempt=0;attempt<64;++attempt){
        check(engine.start(profile),"start before a rejected queued handoff");
#ifdef Q_OS_WIN
        HANDLE writing=nullptr;check(::CreatePipe(&reading,&writing,nullptr,0),"owned rejection fixture pipe");
        engine.attachWindowsPipe("0",quint64(quintptr(writing)),::GetCurrentProcessId(),1400,"192.0.2.1","192.0.2.2");::CloseHandle(writing);
#else
        int descriptors[2];check(::pipe(descriptors)==0,"owned rejection fixture pipe");reading=descriptors[0];
        const auto flags=::fcntl(reading,F_GETFL);check(flags>=0 && ::fcntl(reading,F_SETFL,flags|O_NONBLOCK)==0,"nonblocking ownership observation");
        engine.attachTUN("0",descriptors[1],1400);::close(descriptors[1]);
#endif
        until([&]{return replies==attempt+1;});
#ifdef Q_OS_WIN
        ::CloseHandle(reading);
#else
        ::close(reading);
#endif
        engine.stop();until([&]{return finished==attempt+1;});
    }
}
#endif
#ifndef ABI_FIXTURE
static int originalDNSPreparation(const QJsonObject &config) {
    const auto server = config["server"].toObject(), auth = config["auth"].toObject();
    const auto sources = config["network"].toObject()["original_dns"].toArray();
    check(!sources.isEmpty(), "explicit native DNS fixture sources");
    ConnectionProfile profile;
    profile.endpoint.server = server["host"].toString(); profile.endpoint.port = server["port"].toInt();
    profile.endpoint.authType = auth["method"].toString().mid(QStringLiteral("auth/").size());
    profile.endpoint.authId = auth["auth_id"].toString(); profile.endpoint.authSubType = auth["sub_type"].toString();
    profile.endpoint.phone = auth["phone"].toString(); profile.endpoint.loginDomain = auth["domain"].toString();
    profile.tls.caPem = config["tls"].toObject()["ca_pem"].toString(); profile.keepAlive.mode = "off";
    EmbeddedCoreEngine engine;
    QString generation; bool ready = false, finished = false;
    QJsonObject endpoints; QList<CoreEngine::RequestStatus> replies;
    QObject::connect(&engine, &CoreEngine::sessionStarted, [&](const QString &value) { generation = value; });
    QObject::connect(&engine, &CoreEngine::authenticationRequired, [&](const QJsonObject &request) {
        engine.respond(CoreEngine::responseFor(request, {{"action", "submit"}, {"code", "fixture-code"}}));
    });
    QObject::connect(&engine, &CoreEngine::connectionEstablished, [&] { ready = true; });
    QObject::connect(&engine, &CoreEngine::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "prepared session stops normally"); finished = true;
    });
    QObject::connect(&engine, &CoreEngine::originalDNSPrepared,
        [&](const QString &value, const QJsonObject &listeners, CoreEngine::RequestStatus status) {
            check(value == generation && QThread::currentThread() == QCoreApplication::instance()->thread(), "DNS preparation keeps generation and GUI delivery");
            if (status != CoreEngine::RequestStatus::Success) check(listeners.isEmpty(), "failed preparation cannot expose stale endpoints");
            endpoints = listeners; replies.append(status);
        });
    check(engine.start(profile), "start actual protocol before native DNS preparation");
    until([&] { return ready || finished; }); check(ready && !finished, "authenticated core is ready before source preparation");
    auto invalid = sources; auto bad = invalid[0].toObject(); bad["interface"] = QString(JC_MAX_INPUT, 'x'); invalid[0] = bad;
    engine.prepareOriginalDNS(generation, invalid); until([&] { return replies.size() == 1; });
    check(replies.last() == CoreEngine::RequestStatus::Invalid, "oversized source input did not prepare partial listeners");
    engine.prepareOriginalDNS(generation, sources); until([&] { return replies.size() == 2; });
    check(replies.last() == CoreEngine::RequestStatus::Success && endpoints.size() == 1, "actual Qt/C ABI prepares one source context");
    const auto address = endpoints[sources[0].toObject()["source"].toString()].toString();
    const auto port = address.section(':', -1).toUShort();
    check(address.startsWith("127.0.0.1:") && port, "actual kernel-selected native listener endpoint");
    QTcpSocket idle; idle.connectToHost(QHostAddress::LocalHost, port);
    check(idle.waitForConnected(5000), "prepared native TCP listener is owned before TUN attachment");
    idle.disconnectFromHost();
    check(idle.state() == QAbstractSocket::UnconnectedState || idle.waitForDisconnected(5000), "prepared listener joins a closed idle peer");
    engine.prepareOriginalDNS(generation, sources); until([&] { return replies.size() == 3; });
    check(replies.last() == CoreEngine::RequestStatus::Pending, "prepared source set is sealed");
    engine.prepareOriginalDNS(generation, sources); engine.stop();
    until([&] { return finished && replies.size() == 4; });
    check(replies.last() == CoreEngine::RequestStatus::Stale, "queued preparation cannot claim success after stop");
    QTcpServer tcp; QUdpSocket udp;
    check(tcp.listen(QHostAddress::LocalHost, port) && udp.bind(QHostAddress::LocalHost, port), "ordered stop releases prepared TCP/UDP endpoints");
    std::cout << "PASS: Qt/C ABI ready DNS preparation, sealed sources, queued stop and native endpoint release\n";
    return 0;
}
#endif
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
#ifndef ABI_FIXTURE
    if (argc == 3 && QByteArray(argv[1]) == "--original-dns-gateway") return originalDNSPreparation(QJsonDocument::fromJson(argv[2]).object());
#endif
    const auto info = EmbeddedCoreEngine::buildInfo();
    check(info["abi_version"].toInt() == JC_ABI_VERSION, "loaded library ABI metadata");
    ConnectionProfile profile;
    profile.endpoint.server = "127.0.0.1";
    profile.endpoint.port = 1;
    profile.credentials.password = QString::fromUtf8("private-验证");
    EmbeddedCoreEngine engine;
    QJsonObject request;
    QString generation;
    QList<CoreEngine::RequestStatus> tunReplies;
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
    QObject::connect(&engine, &CoreEngine::tunAttached, [&](const QString &value, CoreEngine::RequestStatus status) {
        check(QThread::currentThread() == app.thread() && value == generation, "TUN result preserves its generation on the GUI thread");
        tunReplies.append(status);
    });
    engine.attachTUN(generation, -1, 1400);
    check(tunReplies.size() == 1 && tunReplies.last() == CoreEngine::RequestStatus::Stale, "idle adapter rejects TUN handoff");
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
    engine.attachTUN(generation, -1, 1400);
    until([&] { return tunReplies.size() == 2; });
    check(tunReplies.last() == CoreEngine::RequestStatus::Unavailable, "fixture driver cannot accept a real TUN device");
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
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_WIN)
    rejectedDeviceHandoffReleasesItsBorrowedHandle(profile);
#endif
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
