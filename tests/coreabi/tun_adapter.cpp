#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "infrastructure/platform/linux/networkhelperclient.h"
#include "tests/platform/networkhelperfixture.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QSaveFile>
#include <QThread>
#include <QTimer>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>

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
    auto engine = std::make_unique<EmbeddedCoreEngine>();
    LinuxNetworkHelperClient helper;
    QList<PlatformOperationResult> helperReplies;
    QList<PlatformOperationResult> helperLosses;
    QObject::connect(&helper, &LinuxNetworkHelperClient::finished, [&](LinuxNetworkHelperClient::Operation, PlatformOperationResult result) {
        helperReplies.append(result);
    });
    QObject::connect(&helper, &LinuxNetworkHelperClient::ownershipLost, [&](PlatformOperationResult result) { helperLosses.append(result); });
    QString generation;
    int ready = 0, finished = 0;
    QList<CoreEngine::RequestStatus> replies;
    QObject::connect(engine.get(), &CoreEngine::sessionStarted, [&](const QString &value) { generation = value; });
    QObject::connect(engine.get(), &CoreEngine::authenticationRequired, [&](const QJsonObject &request) {
        engine->respond(CoreEngine::responseFor(request, {{"action", "submit"}, {"code", "fixture-code"}}));
    });
    QObject::connect(engine.get(), &CoreEngine::connectionEstablished, [&] { ++ready; });
    QObject::connect(engine.get(), &CoreEngine::finished, [&](ConnectionError error) {
        check(error == ConnectionError::NONE, "Qt TUN shutdown succeeds"); ++finished;
    });
    QObject::connect(engine.get(), &CoreEngine::tunAttached, [&](const QString &value, CoreEngine::RequestStatus status) {
        check(QThread::currentThread() == app.thread() && value == generation, "TUN reply preserves GUI thread and generation");
        replies.append(status);
    });
    for (int round = 0; round < 2; ++round) {
        check(tunReferences() == 0, "previous session released every Qt/core TUN reference");
        check(engine->start(profile, CoreEngine::Operation::Connect), "start ordinary Qt core session");
        until([&] { return ready == round + 1; });
        auto configuration = helperFixtureConfiguration({"198.18.0.6/32"},
            EmbeddedCoreEngine::buildInfo()["capabilities"].toObject()["tunnel_mtu"].toInt());
        const bool systemDNS = qgetenv("JC_NATIVE_TUN_DNS") == "1";
        if (systemDNS) configuration.dnsDomains = {"campus.test"};
        const auto owner = round == 0 ? firstOwner : QUuid::createUuid();
        auto helperPrevious = helperReplies.size();
        helper.apply(owner, configuration);
        until([&] { return helperReplies.size() > helperPrevious; });
        check(helperReplies.last().succeeded(), qPrintable(helperReplies.last().detail));
        check(helper.state() == LinuxNetworkHelperClient::State::Active, "installed helper delivered its owned device");
        const quint32 mtu = configuration.mtu;
        const int descriptor = ::fcntl(helper.descriptor(), F_DUPFD_CLOEXEC, 3);
        const int flags = ::fcntl(descriptor, F_GETFL);
        check(flags >= 0 && (flags & O_NONBLOCK) && tunReferences() > 0, "received nonblocking native TUN reference");
        const auto attach = [&](quint32 value) {
            const auto previous = replies.size();
            engine->attachTUN(generation, descriptor, value);
            until([&] { return replies.size() > previous; });
        };
        attach(mtu + 1);
        check(replies.last() == CoreEngine::RequestStatus::Invalid, "Qt preserves kernel MTU rejection");
        check(::fcntl(descriptor, F_GETFL) == flags, "failed handoff preserves caller descriptor and flags");
        const auto previous = replies.size();
        engine->attachTUN(generation, descriptor, mtu);
        ::close(descriptor);
        until([&] { return replies.size() > previous; });
        check(replies.last() == CoreEngine::RequestStatus::Success, "queued fd remains valid after caller closes its reference");
        if (systemDNS) {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            addrinfo *answer = nullptr;
            check(::getaddrinfo("campus.test", nullptr, &hints, &answer) == 0 && answer,
                  "ordinary system resolver reached the core through helper-owned DNS");
            for (auto *entry = answer; entry; entry = entry->ai_next) {
                const auto *address = reinterpret_cast<const sockaddr_in *>(entry->ai_addr);
                check(address->sin_addr.s_addr == ::inet_addr("198.18.0.6"), "system DNS preserved the authorized campus resource");
            }
            ::freeaddrinfo(answer);
            std::cout << "PASS: ordinary getaddrinfo through installed helper and core TUN DNS\n" << std::flush;
        }
        exerciseNativeTUNTraffic();
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
