#include "infrastructure/platform/tundevice.h"
#include <QCoreApplication>
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
#ifndef __APPLE__
#include "infrastructure/platform/linux/iprouteutility.h"
#include "infrastructure/platform/linux/tunroutes.h"
#include "infrastructure/platform/platformcommand.h"
#include <linux/capability.h>
#include <linux/if_tun.h>
#include <sys/syscall.h>
#endif
#include <net/if.h>
#include <poll.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }

#ifndef __APPLE__
enum class Fault { None, ReadbackFailure, VirtualHeader, PacketInformation, ConfigurationReadback, ConfigurationMtu };
static Fault injected = Fault::None;
static int mtuReads = 0;
extern "C" int __real_ioctl(int fd, unsigned long request, ...);
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    if (request == TUNSETPERSIST) {
        const int value = va_arg(args, int);
        va_end(args);
        return __real_ioctl(fd, request, value);
    }
    auto *value = va_arg(args, ifreq *);
    va_end(args);
    if (injected == Fault::ReadbackFailure && request == TUNGETIFF) { errno = EIO; return -1; }
    if (injected == Fault::VirtualHeader && request == TUNSETIFF) value->ifr_flags |= IFF_VNET_HDR;
    if (injected == Fault::PacketInformation && request == TUNSETIFF) value->ifr_flags &= ~IFF_NO_PI;
    const int result = __real_ioctl(fd, request, value);
    if (request == SIOCGIFMTU && ++mtuReads == 2) {
        if (injected == Fault::ConfigurationReadback) { errno = EIO; return -1; }
        if (injected == Fault::ConfigurationMtu) ++value->ifr_mtu;
    }
    return result;
}
#endif

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
    UnixTunDevice device;
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
#ifndef __APPLE__
        __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
        __user_cap_data_struct caps[2]{};
        check(::syscall(SYS_capget, &header, caps) == 0
              && (caps[0].effective | caps[1].effective) == 0,
              "Run the ordinary-user check without root or effective capabilities");
#endif
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
#ifdef __APPLE__
    check(qEnvironmentVariable("GITHUB_ACTIONS") == "true" && qEnvironmentVariable("RUNNER_OS") == "macOS",
          "Allocator check requires a disposable macOS runner");
    constexpr int controlType = SOCK_DGRAM;
#else
    struct stat current{}, initial{};
    check(::stat("/proc/self/ns/net", &current) == 0 && ::stat("/proc/1/ns/net", &initial) == 0
          && (current.st_dev != initial.st_dev || current.st_ino != initial.st_ino), "Refusing the host network namespace");
    constexpr int controlType = SOCK_SEQPACKET;
#endif
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
#ifndef __APPLE__
    for (const auto fault : {Fault::ReadbackFailure, Fault::VirtualHeader, Fault::PacketInformation}) {
        const auto before = interfaces();
        injected = fault;
        const auto failed = device.create(QUuid::createUuid());
        injected = Fault::None;
        check(failed.status == PlatformOperationResult::Status::Failed && failed.mayHaveChanged
              && device.descriptor() == -1 && interfaces() == before,
              "Failed readback or unsupported frame headers were accepted or leaked a device");
    }
    for (const auto fault : {Fault::ConfigurationReadback, Fault::ConfigurationMtu}) {
        const auto before = interfaces();
        const auto routes = runPlatformCommand(trustedIpRouteUtility(), {"-j", "-4", "route", "show", "table", "all"});
        check(routes.result.succeeded(), "Read kernel routes before failed configuration");
        injected = fault;
        mtuReads = 0;
        const auto failed = device.createIpv4(QUuid::createUuid(), "198.18.0.1", "198.18.0.2", 1400);
        injected = Fault::None;
        check(failed.status == PlatformOperationResult::Status::Failed && failed.mayHaveChanged
              && device.snapshot().isEmpty() && interfaces() == before,
              "Failed configuration readback published or leaked an actual configured device");
        const auto after = runPlatformCommand(trustedIpRouteUtility(), {"-j", "-4", "route", "show", "table", "all"});
        check(after.result.succeeded() && after.output == routes.output,
              "Failed device configuration left actual kernel routes behind");
    }
#endif
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
#ifdef Q_OS_LINUX
    check(applied["ipv6_disabled"] == true, "IPv4-only TUN omitted its IPv6 isolation confirmation");
    ifaddrs *addresses = nullptr;
    check(::getifaddrs(&addresses) == 0, "Read configured interface families");
    bool unexpectedIPv6 = false;
    for (auto *entry = addresses; entry; entry = entry->ifa_next)
        if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET6 && QByteArray(entry->ifa_name) == device.name().toLatin1()) unexpectedIPv6 = true;
    ::freeifaddrs(addresses);
    check(!unexpectedIPv6, "IPv4-only TUN generated an IPv6 address");
#endif
    check(!device.createIpv4(QUuid::createUuid(), "198.19.0.1", "198.19.0.2", 1420).succeeded()
          && device.snapshot() == snapshot && device.descriptor() == descriptor,
          "Repeated configured allocation replaced an active owner's device");
#ifndef __APPLE__
    UnixTunDevice collision;
    check(!collision.create(owner).succeeded() && collision.descriptor() == -1
          && ::if_nametoindex(device.name().toLatin1().constData()) == index, "Owner collision attached to or damaged an existing device");
    UnixTunDevice foreign;
    const auto foreignOwner = QUuid::createUuid();
    check(foreign.create(foreignOwner).succeeded(), "Create the external-device fixture");
    const auto foreignName = foreign.name().toLatin1();
    const auto foreignIndex = foreign.index();
    check(::ioctl(foreign.descriptor(), TUNSETPERSIST, 1) == 0, "Retain the external-device fixture without a queue");
    foreign.close();
    const bool refused = !collision.create(foreignOwner).succeeded();
    const bool preserved = ::if_nametoindex(foreignName.constData()) == foreignIndex;
    collision.close();
    // Only the test removes this persistent fixture; the backend must never adopt it.
    const int cleanup = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    ifreq fixture{};
    std::memcpy(fixture.ifr_name, foreignName.constData(), size_t(foreignName.size()));
    fixture.ifr_flags = IFF_TUN | IFF_NO_PI;
    const bool removed = cleanup >= 0 && ::ioctl(cleanup, TUNSETIFF, &fixture) == 0
        && ::ioctl(cleanup, TUNSETPERSIST, 0) == 0;
    if (cleanup >= 0) ::close(cleanup);
    check(removed && refused && preserved, "Persistent external-device collision was adopted, changed or left behind");
#endif
    QJsonObject metadata{{"name", device.name()}, {"index", qint64(index)},
        {"owner", device.owner().toString(QUuid::WithoutBraces)}, {"configuration", configuration}};
#ifndef __APPLE__
    LinuxTunRoutes capture;
    const auto captured = capture.apply(device, "198.18.0.1", "198.18.0.2", {"198.18.0.6/32"});
    check(captured.succeeded(), qPrintable(captured.detail));
    metadata["capture_routes"] = capture.snapshot();
#endif
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
#ifdef __APPLE__
    constexpr int sendFlags = 0;
#else
    constexpr int sendFlags = MSG_NOSIGNAL;
#endif
    check(::sendmsg(control, &message, sendFlags) == payload.size(), "Native allocator did not transfer its owned fd");
    pollfd acknowledgement{control, POLLIN, 0};
    char accepted = 0;
    check(::poll(&acknowledgement, 1, 5000) == 1 && (acknowledgement.revents & POLLIN)
          && ::recv(control, &accepted, 1, MSG_DONTWAIT) == 1 && accepted == 'R',
          "Receiver did not confirm ownership before allocator release");
#ifdef __APPLE__
    std::cout << "PASS: native utun allocator verifies IPv4/MTU configuration, fresh ownership, address-family framing and CLOEXEC before fd transfer\n";
#else
    const auto savedCapture = capture.snapshot();
    device.close();
    std::cout << "TRANSFERRED" << std::endl;
    char finished = 0;
    const auto count = ::recv(control, &finished, 1, 0);
    check(count == 0 || (count == 1 && finished == 'C'), "Invalid fixture cleanup acknowledgement");
    LinuxTunRoutes recovered;
    const auto restored = recovered.recover(owner,savedCapture);
    check(restored.succeeded(),qPrintable(restored.detail));
    std::cout << "PASS: native TUN allocator verifies IPv4/MTU configuration, raw IP framing, readback rollback, exclusive ownership and CLOEXEC before fd transfer\n";
#endif
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
