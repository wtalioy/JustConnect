#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/networkaddress/ipv4.h"
#include <QFileInfo>
#include <QJsonArray>
#include <QScopeGuard>
#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef Q_OS_MACOS
#include <sys/sockio.h>
#endif


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

QJsonObject UnixTunDevice::snapshot() const
{
    if (fd < 0) return {};
    return {{"owner", ownerId.toString(QUuid::WithoutBraces)}, {"interface", interfaceName},
        {"index", qint64(interfaceIndex)}, {"configuration", configuration}};
}

bool UnixTunDevice::validIpv4Configuration(const QString &source, const QString &peer, qint64 mtu)
{
    return canonicalUnicastIpv4(source) && canonicalUnicastIpv4(peer) && source != peer && mtu >= 68 && mtu <= 65535;
}

PlatformOperationResult UnixTunDevice::createIpv4(const QUuid &owner, const QString &source, const QString &peer, int mtu)
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

PlatformOperationResult UnixTunDevice::verifyIpv4(const QString &source, const QString &peer, int mtu, QJsonObject &after) const
{
    using Status = PlatformOperationResult::Status;
    after = readLink(interfaceName, interfaceIndex);
    const QJsonArray expected{QJsonObject{{"source", source}, {"peer", peer}, {"netmask", "255.255.255.255"}}};
    if (after.isEmpty() || after["mtu"].toInt() != mtu || !(after["flags"].toInt() & IFF_UP)
        || after["ipv4"].toArray() != expected)
        return {Status::Failed, "Cannot verify the newly configured TUN device.", true};
    return {Status::Success, {}, true};
}

UnixTunDevice::~UnixTunDevice() { close(); }

void UnixTunDevice::close()
{
    if (fd >= 0) ::close(fd);
    fd = -1;
    interfaceName.clear();
    interfaceIndex = 0;
    ownerId = {};
    configuration = {};
}
