#include "networkhelper.h"
#include <QCoreApplication>
#include <QScopeGuard>
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
// Walk only fixed system components; no request may select a privileged filesystem path.
int storage()
{
    int parent = ::open("/var/lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0) return -1;
    struct stat base{};
    if (::fstat(parent, &base) != 0 || base.st_uid != 0 || (base.st_mode & 0022)) { ::close(parent); return -1; }
    for (const auto *name : {"JustConnect", "network"}) {
        if (::mkdirat(parent, name, 0700) != 0 && errno != EEXIST) { ::close(parent); return -1; }
        const int child = ::openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat info{};
        const bool valid = child >= 0 && ::fstat(child, &info) == 0 && S_ISDIR(info.st_mode)
            && info.st_uid == 0 && (info.st_mode & 07777) == 0700 && ::fsync(parent) == 0;
        ::close(parent);
        if (!valid) { if (child >= 0) ::close(child); return -1; }
        parent = child;
    }
    return parent;
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (::geteuid() != 0 || argc != 3) return 1;
    bool validUid = false, validPid = false;
    const auto invoker = qEnvironmentVariable("PKEXEC_UID");
    const auto callerUid = invoker.toUInt(&validUid);
    const auto caller = app.arguments()[2];
    const auto callerPid = caller.toInt(&validPid);
    const QUuid owner(app.arguments()[1]);
    if (!validUid || callerUid == 0 || QString::number(callerUid) != invoker || !validPid || callerPid <= 0
        || QString::number(callerPid) != caller || owner.isNull() || owner.toString(QUuid::WithoutBraces) != app.arguments()[1]) return 1;
    const int channel = connectLinuxHelper(callerUid, owner);
    if (channel < 0) return 1;
    const auto closeChannel = qScopeGuard([&] { ::close(channel); });
    // Authenticate before creating storage, including on denied/spoofed invocations.
    ucred peer{}; socklen_t size = sizeof(peer);
    if (::getsockopt(channel, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 || size != sizeof(peer)
        || peer.uid != callerUid || peer.pid != callerPid) return 1;
    const int directory = storage();
    if (directory < 0) return 1;
    const auto closeDirectory = qScopeGuard([&] { ::close(directory); });
    return runLinuxNetworkHelper(channel, directory, callerUid, callerPid, owner);
}
