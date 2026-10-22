#include "tundevice.h"
#include "platformcommand.h"
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
#ifdef Q_OS_LINUX
#include "linux/iprouteutility.h"
#endif

namespace {
bool unicast(const QString &text)
{
    in_addr address{};
    if (::inet_pton(AF_INET, text.toLatin1().constData(), &address) != 1) return false;
    char canonical[INET_ADDRSTRLEN]{};
    const auto first = ntohl(address.s_addr) >> 24;
    return first > 0 && first < 224 && first != 127
        && ::inet_ntop(AF_INET, &address, canonical, sizeof(canonical))
        && text == QString::fromLatin1(canonical);
}

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

PlatformOperationResult UnixTunDevice::createIpv4(const QUuid &owner, const QString &source, const QString &peer, int mtu)
{
    using Status = PlatformOperationResult::Status;
    if (!unicast(source) || !unicast(peer) || source == peer || mtu < 68 || mtu > 65535)
        return {Status::Failed, "TUN requires distinct canonical unicast IPv4 addresses and an MTU from 68 through 65535."};
    auto result = create(owner);
    if (!result.succeeded()) return result;
    // Never hand out a partly configured device; its last private fd is the rollback.
    auto rollback = qScopeGuard([&] { close(); });
    const auto before = readLink(interfaceName, interfaceIndex);
    if (before.isEmpty() || !before["ipv4"].toArray().isEmpty())
        return {Status::Failed, "Cannot confirm an unconfigured newly owned TUN device.", true};
#ifdef Q_OS_LINUX
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported, "A trusted system iproute2 executable is required.", true};
    const auto batch = QString("address add %1 peer %2/32 dev %3\nlink set dev %3 mtu %4 up\n")
        .arg(source, peer, interfaceName).arg(mtu).toLatin1();
    result = runPlatformCommand(utility, {"-4", "-batch", "-"}, 5000, batch).result;
#else
    const QFileInfo utility("/sbin/ifconfig");
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)))
        return {Status::Unsupported, "A trusted system ifconfig executable is required.", true};
    result = runPlatformCommand(utility.canonicalFilePath(), {interfaceName, "inet", source, peer,
        "netmask", "255.255.255.255", "mtu", QString::number(mtu), "up"}, 5000).result;
#endif
    if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    const auto after = readLink(interfaceName, interfaceIndex);
    const QJsonArray expected{QJsonObject{{"source", source}, {"peer", peer}, {"netmask", "255.255.255.255"}}};
    if (after.isEmpty() || after["mtu"].toInt() != mtu || !(after["flags"].toInt() & IFF_UP)
        || after["ipv4"].toArray() != expected)
        return {Status::Failed, "Cannot verify the newly configured TUN device.", true};
    configuration = {{"before", before}, {"applied", after}};
    rollback.dismiss();
    return {Status::Success, {}, true};
}
