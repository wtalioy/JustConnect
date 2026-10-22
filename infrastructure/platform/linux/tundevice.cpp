#include "infrastructure/platform/tundevice.h"
#include "infrastructure/platform/platformcommand.h"
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_tun.h>
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

UnixTunDevice::~UnixTunDevice() { close(); }

PlatformOperationResult UnixTunDevice::create(const QUuid &owner)
{
    using Status = PlatformOperationResult::Status;
    if (fd >= 0 || owner.isNull()) return {Status::Failed, QStringLiteral("TUN ownership is missing or already active.")};
    const QFileInfo utility(QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}));
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)))
        return {Status::Unsupported, QStringLiteral("A trusted system iproute2 executable is required.")};
    const int device = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (device < 0) return failed(errno);
    ifreq request{};
    const auto requestedName = QByteArray("jc") + owner.toByteArray(QUuid::Id128).left(IFNAMSIZ - 3);
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
    const auto link = runPlatformCommand(utility.canonicalFilePath(),
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

void UnixTunDevice::close()
{
    if (fd >= 0) ::close(fd);
    fd = -1;
    interfaceName.clear();
    interfaceIndex = 0;
    ownerId = {};
}
