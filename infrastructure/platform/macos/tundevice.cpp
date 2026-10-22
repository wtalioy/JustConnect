#include "infrastructure/platform/tundevice.h"
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

UnixTunDevice::~UnixTunDevice() { close(); }

PlatformOperationResult UnixTunDevice::create(const QUuid &owner)
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

void UnixTunDevice::close()
{
    if (fd >= 0) ::close(fd);
    fd = -1;
    interfaceName.clear();
    interfaceIndex = 0;
    ownerId = {};
    configuration = {};
}
