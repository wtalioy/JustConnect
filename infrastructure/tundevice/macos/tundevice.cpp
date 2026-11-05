#include "infrastructure/tundevice/macos/tundevice.h"
#include "infrastructure/process/command.h"
#include <QFileInfo>
#include <QScopeGuard>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>
#include "infrastructure/networkaddress/ipv4.h"
#include <QJsonArray>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/sockio.h>

namespace {
// XNU's utun control ABI; its private header is not required from the SDK.
constexpr char controlName[] = "com.apple.net.utun_control";
constexpr int optionFlags = 1, optionName = 2;

PlatformOperationResult failed(int error)
{
    using Status = PlatformOperationResult::Status;
    return {error == EACCES || error == EPERM ? Status::PermissionDenied : Status::Failed,
            QStringLiteral("Cannot create an exclusively owned utun device.")};
}
}

PlatformOperationResult MacTunDevice::create(const QUuid &owner)
{
    using Status = PlatformOperationResult::Status;
    if (fd >= 0 || owner.isNull()) return {Status::Failed, QStringLiteral("TUN ownership is missing or already active.")};
    const int device = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (device < 0) return failed(errno);
    ctl_info info{};
    std::memcpy(info.ctl_name, controlName, sizeof(controlName));
    if (::fcntl(device, F_SETFD, FD_CLOEXEC) != 0 || ::ioctl(device, CTLIOCGINFO, &info) != 0) {
        const int error = errno;
        ::close(device);
        return failed(error);
    }
    sockaddr_ctl address{};
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    // Unit zero allocates a fresh interface instead of selecting an existing one.
    if (::connect(device, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        const int error = errno;
        ::close(device);
        return failed(error);
    }
    char name[IFNAMSIZ]{};
    quint32 flags = 0;
    socklen_t nameSize = sizeof(name), flagsSize = sizeof(flags);
    const bool read = ::getsockopt(device, SYSPROTO_CONTROL, optionName, name, &nameSize) == 0
        && ::getsockopt(device, SYSPROTO_CONTROL, optionFlags, &flags, &flagsSize) == 0;
    const bool terminated = nameSize > 0 && nameSize <= sizeof(name) && std::memchr(name, '\0', nameSize);
    const auto actualName = terminated ? QByteArray(name) : QByteArray{};
    const auto actualIndex = terminated ? ::if_nametoindex(name) : 0;
    if (!read || flagsSize != sizeof(flags) || flags != 0 || actualIndex == 0
        || !actualName.startsWith("utun") || actualName.size() <= 4
        || !std::all_of(actualName.cbegin() + 4, actualName.cend(), [](char c) { return c >= '0' && c <= '9'; })) {
        ::close(device);
        return {Status::Failed, QStringLiteral("Cannot verify the newly owned utun device and its address-family framing."), true};
    }
    fd = device;
    interfaceName = QString::fromLatin1(actualName);
    interfaceIndex = actualIndex;
    ownerId = owner;
    return {};
}

PlatformOperationResult MacTunDevice::configureIpv4(const QString &source, const QString &peer, int mtu, QJsonObject &after)
{
    using Status = PlatformOperationResult::Status;
    PlatformOperationResult result;
    const QFileInfo utility("/sbin/ifconfig");
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)))
        return {Status::Unsupported, "A trusted system ifconfig executable is required.", true};
    result = runPlatformCommand(utility.canonicalFilePath(), {interfaceName, "inet", source, peer,
        "netmask", "255.255.255.255", "mtu", QString::number(mtu), "up"}, 5000).result;
    if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    result = verifyIpv4(source, peer, mtu, after);
    if (!result.succeeded()) return result;
    return {Status::Success, {}, true};
}



namespace {

QJsonObject readLink(const QString &name, quint32 index)
{
    if (::if_nametoindex(name.toLatin1().constData()) != index) return {};
    const int socket = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket < 0) return {};
    const auto close = qScopeGuard([&] { ::close(socket); });
    if (::fcntl(socket, F_SETFD, FD_CLOEXEC) != 0) return {};
    ifreq request{};
    const auto bytes = name.toLatin1();
    if (bytes.size() >= IFNAMSIZ) return {};
    std::copy(bytes.cbegin(), bytes.cend(), request.ifr_name);
    if (::ioctl(socket, SIOCGIFFLAGS, &request) != 0) return {};
    const auto flags = quint16(request.ifr_flags);
    if (::ioctl(socket, SIOCGIFMTU, &request) != 0) return {};
    const int mtu = request.ifr_mtu;
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return {};
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    QJsonArray rows;
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (QString::fromLatin1(entry->ifa_name) != name || !entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET) continue;
        if (!(entry->ifa_flags & IFF_POINTOPOINT) || !entry->ifa_dstaddr || !entry->ifa_netmask
            || entry->ifa_dstaddr->sa_family != AF_INET || entry->ifa_netmask->sa_family != AF_INET) return {};
        const auto address = [](const sockaddr *value) {
            char text[INET_ADDRSTRLEN]{};
            const auto *ip = reinterpret_cast<const sockaddr_in *>(value);
            return ::inet_ntop(AF_INET, &ip->sin_addr, text, sizeof(text)) ? QString::fromLatin1(text) : QString{};
        };
        rows.append(QJsonObject{{"source", address(entry->ifa_addr)}, {"peer", address(entry->ifa_dstaddr)},
            {"netmask", address(entry->ifa_netmask)}});
    }
    if (::if_nametoindex(bytes.constData()) != index) return {};
    return {{"mtu", mtu}, {"flags", flags}, {"ipv4", rows}};
}
}

QJsonObject MacTunDevice::snapshot() const
{
    if (fd < 0) return {};
    return {{"owner", ownerId.toString(QUuid::WithoutBraces)}, {"interface", interfaceName},
        {"index", qint64(interfaceIndex)}, {"configuration", configuration}};
}

bool MacTunDevice::validIpv4Configuration(const QString &source, const QString &peer, qint64 mtu)
{
    return canonicalUnicastIpv4(source) && canonicalUnicastIpv4(peer) && source != peer && mtu >= 68 && mtu <= 65535;
}

PlatformOperationResult MacTunDevice::createIpv4(const QUuid &owner, const QString &source, const QString &peer, int mtu)
{
    using Status = PlatformOperationResult::Status;
    if (!validIpv4Configuration(source, peer, mtu))
        return {Status::Failed, "TUN requires distinct canonical unicast IPv4 addresses and an MTU from 68 through 65535."};
    auto result = create(owner);
    if (!result.succeeded()) return result;
    // Never hand out a partly configured device; its last private fd is the rollback.
    auto rollback = qScopeGuard([&] { close(); });
    const auto before = readLink(interfaceName, interfaceIndex);
    if (before.isEmpty() || !before["ipv4"].toArray().isEmpty())
        return {Status::Failed, "Cannot confirm an unconfigured newly owned TUN device.", true};
    QJsonObject after;
    result = configureIpv4(source, peer, mtu, after);
    if (!result.succeeded()) return result;
    configuration = {{"before", before}, {"applied", after}};
    rollback.dismiss();
    return {Status::Success, {}, true};
}

PlatformOperationResult MacTunDevice::verifyIpv4(const QString &source, const QString &peer, int mtu, QJsonObject &after) const
{
    using Status = PlatformOperationResult::Status;
    after = readLink(interfaceName, interfaceIndex);
    const QJsonArray expected{QJsonObject{{"source", source}, {"peer", peer}, {"netmask", "255.255.255.255"}}};
    if (after.isEmpty() || after["mtu"].toInt() != mtu || !(after["flags"].toInt() & IFF_UP)
        || after["ipv4"].toArray() != expected)
        return {Status::Failed, "Cannot verify the newly configured TUN device.", true};
    return {Status::Success, {}, true};
}

MacTunDevice::~MacTunDevice() { close(); }

void MacTunDevice::close()
{
    if (fd >= 0) ::close(fd);
    fd = -1;
    interfaceName.clear();
    interfaceIndex = 0;
    ownerId = {};
    configuration = {};
}
