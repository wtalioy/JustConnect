#include "infrastructure/platform/tundevice.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#ifndef __APPLE__
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
enum class Fault { None, ReadbackFailure, VirtualHeader, PacketInformation };
static Fault injected = Fault::None;
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
    return __real_ioctl(fd, request, value);
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
    if (argc == 1) {
        check(::geteuid() != 0, "Run the ordinary-user check without root");
#ifndef __APPLE__
        __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
        __user_cap_data_struct caps[2]{};
        check(::syscall(SYS_capget, &header, caps) == 0
              && (caps[0].effective | caps[1].effective) == 0,
              "Run the ordinary-user check without root or effective capabilities");
#endif
        check(!device.create({}).succeeded(), "Missing ownership reached TUN creation");
        const auto denied = device.create(QUuid::createUuid());
        check(denied.status == PlatformOperationResult::Status::PermissionDenied && !denied.mayHaveChanged
              && device.descriptor() == -1 && device.name().isEmpty(), "Unprivileged creation changed network state or hid permission denial");
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
#endif
    const auto before = interfaces();
    const auto owner = QUuid::createUuid();
    const auto result = device.create(owner);
    check(result.succeeded(), qPrintable(result.detail));
    const auto descriptor = device.descriptor();
    const auto index = device.index();
    check((::fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0 && !before.contains(device.name()),
          "Borrowed TUN fd can leak across exec or adopted an existing interface");
    check(!device.create(QUuid::createUuid()).succeeded() && device.descriptor() == descriptor
          && device.index() == index && device.owner() == owner,
          "Repeated creation changed the owned device");
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
    const auto payload = QJsonDocument(QJsonObject{{"name", device.name()}, {"index", qint64(index)},
        {"owner", device.owner().toString(QUuid::WithoutBraces)}}).toJson(QJsonDocument::Compact);
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
    std::cout << "PASS: native utun allocator verifies fresh ownership, address-family framing and CLOEXEC before fd transfer\n";
#else
    std::cout << "PASS: native TUN allocator verifies raw IP framing, readback rollback, exclusive ownership and CLOEXEC before fd transfer\n";
#endif
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
