#include "infrastructure/networkhelper/linux/networkhelper.h"
#include "networkhelperpaths.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
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
static void isolated()
{
    struct stat current{}, initial{};
    check(::geteuid() == 0 && ::stat("/proc/thread-self/ns/net", &current) == 0 && ::stat("/proc/1/ns/net", &initial) == 0
        && (current.st_dev != initial.st_dev || current.st_ino != initial.st_ino), "Refusing the host network namespace");
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    if (argc == 3 && app.arguments()[1] == "--scan-isolated") {
        isolated();
        bool valid = false;
        const int directory = app.arguments()[2].toInt(&valid);
        check(valid && directory >= 3, "Invalid private recovery directory fixture");
        const auto summary = recoverLinuxHelperRecords(directory);
        std::cout << QJsonDocument(summary.json()).toJson(QJsonDocument::Compact).constData() << '\n';
        return summary.succeeded() ? 0 : 1;
    }
    if (argc == 6) {
        isolated();
        check(app.arguments()[1] == "--isolated", "Invalid private helper fixture mode");
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
    check(!recoverLinuxHelperRecords(-1).succeeded(), "Ordinary caller acquired system recovery authority");
    QProcess version;
    version.start(app.applicationDirPath() + '/' + QFileInfo(QString::fromLatin1(LinuxNetworkHelperPath)).fileName(), {"--version"});
    check(version.waitForFinished(3000) && version.exitStatus() == QProcess::NormalExit && version.exitCode() == 0,
        "Helper runtime inspection requires privilege or failed to start");
    const auto facts = QJsonDocument::fromJson(version.readAllStandardOutput()).object();
    check(facts.size() == 5 && facts["worker"] == "network-helper" && facts["protocol"] == LinuxHelperProtocol
        && facts["qt"] == qVersion() && facts["revision"].toString().size() == 40
        && QStringList{"clean", "dirty", "archive"}.contains(facts["source_state"].toString()),
        "Helper runtime identity, provenance or protocol does not match the caller");
    const auto owner = QUuid::createUuid();
    LinuxHelperConfiguration configuration;
    configuration.address = "198.18.0.1"; configuration.peer = "198.18.0.2"; configuration.mtu = 1400;
    configuration.capturePrefixes = {"198.18.4.0/24"};
    configuration.originalInterface = "fixture0"; configuration.originalSource = "192.0.2.1";
    configuration.originalPrefixes = configuration.capturePrefixes;
    configuration.dnsDomains = {"campus.test", "research.test"};
    const auto encoded = linuxHelperApplyRequest(owner, configuration);
    const auto parsed = parseLinuxHelperApply(owner, encoded);
    check(parsed && linuxHelperApplyRequest(owner, *parsed) == encoded, "Typed configuration lost validated input");
    const auto extension = linuxHelperExtendRequest(owner,{"198.18.6.7","198.18.6.7"});
    const auto extended = parseLinuxHelperExtend(owner,extension);
    check(extended && *extended == QStringList{"198.18.6.7"},"Typed DNS route input lost or duplicated its address");
    for (const auto &address : {QString(),QString("0.0.0.0"),QString("127.0.0.1"),QString("224.0.0.1"),
                               QString("198.18.6.0/24"),QString("198.18.6.7\nrule del priority 0"),QString("example.test")})
        check(!parseLinuxHelperExtend(owner,linuxHelperExtendRequest(owner,{address})),"Unsafe DNS route input accepted");
    auto badExtension = extension;
    badExtension["addresses"] = QJsonArray{7};
    check(!parseLinuxHelperExtend(owner,badExtension),"Non-string DNS address accepted");
    badExtension = extension; badExtension["program"] = "/bin/sh";
    check(!parseLinuxHelperExtend(owner,badExtension) && !parseLinuxHelperExtend(QUuid::createUuid(),extension),
          "Extra authority or another owner entered DNS route publication");
    const auto replacement = linuxHelperRoutesRequest(owner,{"198.18.8.0/24","198.18.8.0/24"});
    check(parseLinuxHelperRoutes(owner,replacement) == std::optional<QStringList>{{"198.18.8.0/24"}}
          && parseLinuxHelperRoutes(owner,linuxHelperRoutesRequest(owner,{})).has_value(),"Route set parsing lost duplicates or empty withdrawal");
    auto invalidRoutes = replacement; invalidRoutes["path"] = "/tmp/foreign";
    check(!parseLinuxHelperRoutes(owner,invalidRoutes) && !parseLinuxHelperRoutes(QUuid::createUuid(),replacement),
          "Route replacement accepted external authority or another owner");
    for (const auto &prefix : {"default","0.0.0.0/0","198.18.8.7/24","198.18.8.0/24\nrule del priority 0"})
        check(!parseLinuxHelperRoutes(owner,linuxHelperRoutesRequest(owner,{QString::fromLatin1(prefix)})),"Unsafe route replacement accepted");
    auto invalid = encoded;
    invalid.remove("dns");
    check(!parseLinuxHelperApply(owner, invalid), "Missing DNS intent silently became an IP-only connection");
    invalid = encoded;
    invalid["dns"] = QJsonArray{"campus.test", 7};
    check(!parseLinuxHelperApply(owner, invalid), "Non-string DNS routing domain accepted");
    invalid = encoded;
    invalid["underlay"] = QJsonObject{{"interface", "fixture0"}, {"source", "192.0.2.1"}, {"prefixes", QJsonArray{"198.18.4.0/24"}}};
    check(!parseLinuxHelperApply(owner, invalid), "Missing gateway was silently converted to an empty gateway");
    check(!parseLinuxHelperApply(QUuid::createUuid(), encoded), "Typed decoder accepted another connection owner");
    configuration.originalInterface = "fixture0; id";
    check(!parseLinuxHelperApply(owner, linuxHelperApplyRequest(owner, configuration)), "Client validation diverged from native interface rules");
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
