#include "infrastructure/platform/linux/networkhelper.h"
#include "networkhelperpaths.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    if (argc == 6) {
        struct stat current{}, initial{};
        check(::geteuid() == 0 && app.arguments()[1] == "--isolated"
            && ::stat("/proc/thread-self/ns/net", &current) == 0 && ::stat("/proc/1/ns/net", &initial) == 0
            && (current.st_dev != initial.st_dev || current.st_ino != initial.st_ino), "Refusing the host network namespace");
        bool directoryValid = false, uidValid = false, pidValid = false;
        const int directory = app.arguments()[2].toInt(&directoryValid);
        const auto uid = app.arguments()[3].toUInt(&uidValid);
        const auto pid = app.arguments()[4].toInt(&pidValid);
        const QUuid owner(app.arguments()[5]);
        check(directoryValid && uidValid && pidValid && directory >= 3 && uid != 0 && pid > 0 && !owner.isNull(), "Invalid isolated helper fixture");
        // Only this test binary accepts an inherited fixture directory; the product has a fixed system path.
        const int socket = connectLinuxHelper(uid, owner);
        check(socket >= 0, "Connect to ordinary caller's private listener");
        const int result = runLinuxNetworkHelper(socket, directory, uid, pid, owner);
        ::close(socket);
        return result;
    }
    check(argc == 1 && ::geteuid() != 0, "Run ordinary IPC checks without root");
    QProcess version;
    version.start(app.applicationDirPath() + '/' + QFileInfo(QString::fromLatin1(LinuxNetworkHelperPath)).fileName(), {"--version"});
    check(version.waitForFinished(3000) && version.exitStatus() == QProcess::NormalExit && version.exitCode() == 0,
        "Helper runtime inspection requires privilege or failed to start");
    const auto facts = QJsonDocument::fromJson(version.readAllStandardOutput()).object();
    check(facts.size() == 5 && facts["worker"] == "network-helper" && facts["protocol"] == LinuxHelperProtocol
        && facts["qt"] == qVersion() && facts["revision"].toString().size() == 40
        && QStringList{"clean", "dirty", "archive"}.contains(facts["source_state"].toString()),
        "Helper runtime identity, provenance or protocol does not match the caller");
    int sockets[2];
    check(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0, "Create private packet sockets");
    const QJsonObject original{{"version", LinuxHelperProtocol}, {"value", "framed packet"}};
    check(sendLinuxHelperPacket(sockets[0], original).succeeded(), "Send framed JSON");
    QJsonObject packet; int received = -1;
    check(receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded() && packet == original && received == -1, "JSON framing changed values");
    const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(fd >= 0 && sendLinuxHelperPacket(sockets[0], original, fd).succeeded(), "Send owned descriptor");
    check(receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded() && received >= 0
        && (::fcntl(received, F_GETFD) & FD_CLOEXEC), "Received descriptor is missing or inheritable");
    ::close(received); ::close(fd);
    const auto beforeDescriptors = QDir("/proc/self/fd").entryList(QDir::NoDotAndDotDot | QDir::AllEntries).size();
    int extra[2] = {::open("/dev/null", O_RDONLY | O_CLOEXEC), ::open("/dev/null", O_RDONLY | O_CLOEXEC)};
    check(extra[0] >= 0 && extra[1] >= 0, "Create excess descriptor fixture");
    char payload = 'x'; iovec data{&payload, 1};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(extra))]{};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    auto *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(extra));
    std::memcpy(CMSG_DATA(header), extra, sizeof(extra));
    check(::sendmsg(sockets[0], &message, MSG_NOSIGNAL) == 1, "Send excess descriptors");
    ::close(extra[0]); ::close(extra[1]);
    check(!receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded() && received == -1
        && QDir("/proc/self/fd").entryList(QDir::NoDotAndDotDot | QDir::AllEntries).size() == beforeDescriptors,
        "Rejected ancillary descriptors leaked into the receiver");
    const auto malformed = QByteArray("[]");
    check(::send(sockets[0], malformed.constData(), malformed.size(), MSG_NOSIGNAL) == malformed.size()
        && !receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded() && received == -1, "Non-object packet accepted");
    QJsonObject excessive{{"value", QString(LinuxHelperPacketBytes, 'x')}};
    check(!sendLinuxHelperPacket(sockets[0], excessive).succeeded(), "Oversized packet sent");
    const QByteArray oversized(LinuxHelperPacketBytes + 1, 'x');
    check(::send(sockets[0], oversized.constData(), oversized.size(), MSG_NOSIGNAL) == oversized.size()
        && !receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded(), "Truncated packet accepted");
    check(!receiveLinuxHelperPacket(sockets[1], packet, received, 1).succeeded(), "Empty channel ignored timeout");
    check(runLinuxNetworkHelper(sockets[1], -1, ::getuid(), ::getpid(), QUuid::createUuid()) != 0, "Ordinary process entered privileged operations");
    ::close(sockets[0]);
    check(!receiveLinuxHelperPacket(sockets[1], packet, received, 1000).succeeded(), "EOF accepted as a packet");
    ::close(sockets[1]);
    std::cout << "PASS: bounded helper IPC, CLOEXEC fd transfer, malformed/truncated rejection and privilege boundary\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
