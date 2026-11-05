#include "infrastructure/tundevice/macos/tundevice.h"
#include <QCoreApplication>
#include <QFile>
#include <ifaddrs.h>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include "infrastructure/routing/macos/tunroutes.h"
#include <QTemporaryDir>
#include <net/if.h>
#include <poll.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }


static QMap<QString, unsigned int> interfaces()
{
    auto *entries = ::if_nameindex();
    check(entries != nullptr, "Read actual namespace interfaces");
    QMap<QString, unsigned int> result;
    for (auto *entry = entries; entry->if_index != 0; ++entry)
        result[QString::fromLatin1(entry->if_name)] = entry->if_index;
    ::if_freenameindex(entries);
    return result;
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    MacTunDevice device;
    const auto originalInterfaces = interfaces();
    const auto invalidConfiguration = [&] {
        for (const auto &bad : {QString("0.0.0.0"), QString("127.0.0.1"), QString("224.0.0.1"),
                               QString("198.018.0.1"), QString("::1"), QString("198.18.0.1") + QChar(0) + "ignored"})
            check(!device.createIpv4(QUuid::createUuid(), bad, "198.18.0.2", 1400).succeeded()
                  && device.snapshot().isEmpty(), "Invalid source reached configured TUN allocation");
        for (const int mtu : {0, 67, 65536})
            check(!device.createIpv4(QUuid::createUuid(), "198.18.0.1", "198.18.0.2", mtu).succeeded(),
                  "Invalid MTU reached configured TUN allocation");
        check(!device.createIpv4(QUuid::createUuid(), "198.18.0.1", "198.18.0.1", 1400).succeeded()
              && !device.createIpv4(QUuid::createUuid(), "198.18.0.1", "224.0.0.1", 1400).succeeded()
              && interfaces() == originalInterfaces, "Invalid point-to-point addresses changed interfaces");
    };
    if (argc == 1) {
        check(::geteuid() != 0, "Run the ordinary-user check without root");
        invalidConfiguration();
        check(!device.create({}).succeeded(), "Missing ownership reached TUN creation");
        const auto denied = device.create(QUuid::createUuid());
        check(denied.status == PlatformOperationResult::Status::PermissionDenied && !denied.mayHaveChanged
              && device.descriptor() == -1 && device.name().isEmpty(), "Unprivileged creation changed network state or hid permission denial");
        const auto configured = device.createIpv4(QUuid::createUuid(), "198.18.0.1", "198.18.0.2", 1400);
        check(configured.status == PlatformOperationResult::Status::PermissionDenied && !configured.mayHaveChanged
              && device.snapshot().isEmpty() && interfaces() == originalInterfaces,
              "Unprivileged configured allocation changed the network or lost its permission result");
        std::cout << "PASS: native TUN creation requires device privileges and a valid owner\n";
        return 0;
    }
    check(argc == 2 && ::geteuid() == 0, "Allocator check requires root and one inherited socket");
    check(qEnvironmentVariable("GITHUB_ACTIONS") == "true" && qEnvironmentVariable("RUNNER_OS") == "macOS",
          "Allocator check requires a disposable macOS runner");
    constexpr int controlType = SOCK_DGRAM;
    bool valid = false;
    const int control = app.arguments()[1].toInt(&valid);
    int type = 0;
    socklen_t size = sizeof(type);
    check(valid && control >= 3 && ::getsockopt(control, SOL_SOCKET, SO_TYPE, &type, &size) == 0
          && type == controlType, "Allocator requires its inherited packet socket");
    const int descriptorFlags = ::fcntl(control, F_GETFD);
    check(descriptorFlags >= 0 && ::fcntl(control, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0,
          "Allocator control channel can leak across exec");
    invalidConfiguration();
    const auto before = interfaces();
    const auto owner = QUuid::createUuid();
    const auto result = device.createIpv4(owner, "198.18.0.1", "198.18.0.2", 1400);
    check(result.succeeded(), qPrintable(result.detail));
    const auto descriptor = device.descriptor();
    const auto index = device.index();
    check((::fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0 && !before.contains(device.name()),
          "Borrowed TUN fd can leak across exec or adopted an existing interface");
    check(!device.create(QUuid::createUuid()).succeeded() && device.descriptor() == descriptor
          && device.index() == index && device.owner() == owner,
          "Repeated creation changed the owned device");
    const auto snapshot = device.snapshot();
    const auto configuration = snapshot["configuration"].toObject();
    const auto applied = configuration["applied"].toObject();
    check(configuration["before"].toObject()["ipv4"].toArray().isEmpty()
          && applied["mtu"] == 1400 && (applied["flags"].toInt() & IFF_UP)
          && applied["ipv4"].toArray() == QJsonArray{QJsonObject{{"source", "198.18.0.1"},
              {"peer", "198.18.0.2"}, {"netmask", "255.255.255.255"}}},
          "Device ownership lost its original and verified applied configuration");
    check(!device.createIpv4(QUuid::createUuid(), "198.19.0.1", "198.19.0.2", 1420).succeeded()
          && device.snapshot() == snapshot && device.descriptor() == descriptor,
          "Repeated configured allocation replaced an active owner's device");
    QJsonObject metadata{{"name", device.name()}, {"index", qint64(index)},
        {"owner", device.owner().toString(QUuid::WithoutBraces)}, {"configuration", configuration}};
    QTemporaryDir ownershipDirectory;
    check(ownershipDirectory.isValid(), "Create a protected native capture journal");
    const int journalDirectory = ::open(QFile::encodeName(ownershipDirectory.path()).constData(), O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    check(journalDirectory >= 0, "Open protected native capture storage");
    MacNetworkJournal journal;
    check(journal.open(journalDirectory, owner).succeeded(), "Acquire native capture journal authority");
    const auto checkpoint = [&](const QJsonObject &record) { return record.isEmpty() ? journal.remove() : journal.store(record); };
    MacTunRoutes capture;
    const auto captured = capture.apply(device, {"198.18.0.6/32"}, checkpoint);
    check(captured.succeeded(), qPrintable(captured.detail));
    metadata["capture_routes"] = capture.snapshot();
    const auto payload = QJsonDocument(metadata).toJson(QJsonDocument::Compact);
    iovec data{const_cast<char *>(payload.constData()), size_t(payload.size())};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    auto *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    constexpr int sendFlags = 0;
    check(::sendmsg(control, &message, sendFlags) == payload.size(), "Native allocator did not transfer its owned fd");
    pollfd acknowledgement{control, POLLIN, 0};
    char accepted = 0;
    check(::poll(&acknowledgement, 1, 5000) == 1 && (acknowledgement.revents & POLLIN)
          && ::recv(control, &accepted, 1, MSG_DONTWAIT) == 1 && accepted == 'R',
          "Receiver did not confirm ownership before allocator release");
    const auto savedCapture = capture.snapshot();
    device.close();
    std::cout << "TRANSFERRED" << std::endl;
    char finished = 0;
    pollfd cleanupRequest{control, POLLIN, 0};
    check(::poll(&cleanupRequest, 1, 120000) == 1 && (cleanupRequest.revents & POLLIN), "Native allocator cleanup acknowledgement timed out");
    const auto count = ::recv(control, &finished, 1, 0);
    check(count == 0 || (count == 1 && finished == 'C'), "Invalid fixture cleanup acknowledgement");
    QJsonObject saved;
    check(journal.load(saved).succeeded() && saved == savedCapture, "Protected capture record changed before recovery");
    const auto observed = readMacRoutes();
    check(observed.result.succeeded(), qPrintable(observed.result.detail));
    QJsonArray current;
    for (const auto &row : observed.rows)
        if (row.toObject()["prefix"] == "198.18.0.6/32") current.append(row);
    std::cout << "CAPTURE_OBSERVATION " << QJsonDocument(QJsonObject{{"record",saved},{"current",current}}).toJson(QJsonDocument::Compact).constData() << std::endl;
    MacTunRoutes recovered;
    const auto restored = recovered.recover(owner, saved, checkpoint);
    journal.close(); ::close(journalDirectory);
    check(restored.succeeded(),qPrintable(restored.detail));
    std::cout << "PASS: native TUN allocator verifies configuration, framing, exclusive fd ownership and capture recovery\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
