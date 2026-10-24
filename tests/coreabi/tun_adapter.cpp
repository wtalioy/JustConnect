#include "infrastructure/coreengine/embeddedcoreengine.h"
#include "tuntraffic.h"
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QThread>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory>
#include <cstring>

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
static int acquire(int control, quint32 &mtu) {
    check(::send(control, "A", 1, MSG_NOSIGNAL) == 1, "request owned device after initial protection");
    char data[32] = {};
    iovec part{data, sizeof(data)};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))] = {};
    msghdr message{};
    message.msg_iov = &part; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    const auto size = ::recvmsg(control, &message, MSG_CMSG_CLOEXEC);
    check(size > 0 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)), "receive native helper descriptor");
    auto *header = CMSG_FIRSTHDR(&message);
    check(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
        && header->cmsg_len == CMSG_LEN(sizeof(int)), "one owned TUN descriptor received");
    int descriptor = -1;
    std::memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
    bool valid = false;
    mtu = QByteArray(data, size).toUInt(&valid);
    check(valid && descriptor >= 0, "native helper returned device MTU");
    return descriptor;
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    check(argc == 4 && QByteArray(argv[1]) == "--tun-gateway", "requires native gateway fixture");
    check(::getuid() != 0 && ::getuid() == ::geteuid(), "Qt data plane stays unprivileged");
    const int control = QByteArray(argv[3]).toInt();
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
        quint32 mtu = 0;
        const int descriptor = acquire(control, mtu);
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
        exerciseNativeTUNTraffic();
        // Queue another owned reference immediately before stop/destruction.
        const int retained = acquire(control, mtu);
        engine->attachTUN(generation, retained, mtu);
        ::close(retained);
        if (round == 0) {
            engine->stop();
            until([&] { return finished == 1; });
            until([&] { return replies.size() == previous + 2; });
            check(replies.last() == CoreEngine::RequestStatus::Stale, "queued reply becomes stale during stop");
        } else engine.reset();
        check(tunReferences() == 0, "stop/destruction releases active and queued references");
        check(::send(control, "R", 1, MSG_NOSIGNAL) == 1, "release root fixture reference");
        char response = 0;
        check(::recv(control, &response, 1, 0) == 1 && response == 'R', "owned routes removed before next session snapshot");
    }
    std::cout << "PASS: ordinary native TCP/UDP via queued Qt fd handoff, stop, restart and destruction\n";
}
