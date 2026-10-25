#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/process/command.h"
#include <QFileInfo>
#include <QScopeGuard>
#include "infrastructure/process/command.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {
PlatformOperationResult failed(int error)
{
    using Status = PlatformOperationResult::Status;
    return {error == EACCES || error == EPERM ? Status::PermissionDenied : Status::Failed,
            QStringLiteral("Cannot create an exclusively owned TUN device.")};
}
}

PlatformOperationResult UnixTunDevice::create(const QUuid &owner)
{
    using Status = PlatformOperationResult::Status;
    if (fd >= 0 || owner.isNull()) return {Status::Failed, QStringLiteral("TUN ownership is missing or already active.")};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty())
        return {Status::Unsupported, QStringLiteral("A trusted system iproute2 executable is required.")};
    const int device = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (device < 0) return failed(errno);
    ifreq request{};
    const auto requestedName = linuxTunName(owner);
    std::memcpy(request.ifr_name, requestedName.constData(), size_t(requestedName.size()));
    request.ifr_flags = short(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    if (::ioctl(device, TUNSETIFF, &request) != 0) {
        const int error = errno;
        ::close(device);
        return failed(error);
    }
    ifreq actual{};
    const auto actualIndex = ::if_nametoindex(request.ifr_name);
    if (::ioctl(device, TUNGETIFF, &actual) != 0 || actualIndex == 0
        || QByteArray(actual.ifr_name) != requestedName
        || (actual.ifr_flags & (IFF_TUN | IFF_TAP | IFF_VNET_HDR | IFF_MULTI_QUEUE | IFF_PERSIST)) != IFF_TUN) {
        ::close(device);
        return {Status::Failed, QStringLiteral("Cannot verify the newly owned TUN device."), true};
    }
    // TUNGETIFF aliases NO_PI with NOFILTER; link details expose the actual framing state.
    const auto link = runPlatformCommand(utility,
        {"-j", "-d", "link", "show", "dev", QString::fromLatin1(requestedName)}, 1000);
    const auto bytes = link.output.toUtf8();
    const auto rows = bytes.size() <= 65536 ? QJsonDocument::fromJson(bytes).array() : QJsonArray{};
    const auto row = rows.size() == 1 ? rows.first().toObject() : QJsonObject{};
    const auto info = row["linkinfo"].toObject(), data = info["info_data"].toObject();
    if (!link.result.succeeded() || row["ifindex"].toInteger(-1) != actualIndex
        || row["ifname"] != QString::fromLatin1(requestedName) || info["info_kind"] != "tun" || data["type"] != "tun"
        || data["pi"] != QJsonValue(false) || data["vnet_hdr"] != QJsonValue(false)
        || data["persist"] != QJsonValue(false) || data["multi_queue"] != QJsonValue(false)) {
        ::close(device);
        return {link.result.succeeded() ? Status::Failed : link.result.status,
                QStringLiteral("Cannot verify raw IP framing for the newly owned TUN device."), true};
    }
    fd = device;
    interfaceName = QString::fromLatin1(requestedName);
    interfaceIndex = actualIndex;
    ownerId = owner;
    return {};
}

PlatformOperationResult UnixTunDevice::configureIpv4(const QString &source, const QString &peer, int mtu, QJsonObject &after)
{
    using Status = PlatformOperationResult::Status;
    PlatformOperationResult result;
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported, "A trusted system iproute2 executable is required.", true};
    // This newly owned IPv4-only interface must not add IPv6 link-local or multicast routes.
    const auto ipv6Path = QString("/proc/sys/net/ipv6/conf/%1/disable_ipv6").arg(interfaceName).toLocal8Bit();
    const int ipv6 = ::open(ipv6Path.constData(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    const auto closeIpv6 = qScopeGuard([&] { if (ipv6 >= 0) ::close(ipv6); });
    struct statfs filesystem{};
    if (ipv6 < 0 ? (errno != ENOENT || QFileInfo::exists("/proc/sys/net/ipv6/conf"))
        : (::fstatfs(ipv6, &filesystem) != 0 || filesystem.f_type != PROC_SUPER_MAGIC
            || ::write(ipv6, "1\n", 2) != 2))
        return {Status::Failed, "Cannot isolate IPv6 on the newly owned IPv4 TUN.", true};
    const auto ipv6Disabled = [&] {
        char value[4]{};
        return ipv6 < 0 || (::lseek(ipv6, 0, SEEK_SET) == 0 && ::read(ipv6, value, sizeof(value)) == 2
            && value[0] == '1' && value[1] == '\n');
    };
    if (!ipv6Disabled()) return {Status::Failed, "Cannot confirm IPv6 isolation on the new TUN.", true};
    const auto batch = QString("address add %1 peer %2/32 dev %3\nlink set dev %3 mtu %4 up\n")
        .arg(source, peer, interfaceName).arg(mtu).toLatin1();
    result = runPlatformCommand(utility, {"-4", "-batch", "-"}, 5000, batch).result;
    if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    result = verifyIpv4(source, peer, mtu, after);
    if (!result.succeeded()) return result;
    if (!ipv6Disabled()) return {Status::Failed, "IPv6 isolation changed during TUN configuration.", true};
    after["ipv6_disabled"] = true;
    return {Status::Success, {}, true};
}
