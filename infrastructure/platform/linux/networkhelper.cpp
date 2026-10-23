#include "networkhelper.h"
#include "sourcejournal.h"
#include "sourceroutes.h"
#include "tunroutes.h"
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QScopeGuard>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr int packetTimeoutMs = 5000, handshakeTimeoutMs = 30000;
Result invalid(const char *message) { return {Status::Failed, QString::fromLatin1(message)}; }
bool fields(const QJsonObject &object, std::initializer_list<const char *> keys)
{
    if (object.size() != qsizetype(keys.size())) return false;
    for (const auto *key : keys) if (!object.contains(QLatin1String(key))) return false;
    return true;
}
bool waitFor(int socket, short events, QDeadlineTimer &deadline)
{
    pollfd item{socket, events, 0};
    for (;;) {
        const int status = ::poll(&item, 1, int(deadline.remainingTime()));
        if (status < 0 && errno == EINTR && !deadline.hasExpired()) continue;
        return status > 0 && (item.revents & events);
    }
}
int privateDirectory(int parent, const QByteArray &name)
{
    if (::mkdirat(parent, name.constData(), 0700) != 0 && errno != EEXIST) return -1;
    const int fd = ::openat(parent, name.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info{};
    if (fd < 0) return -1;
    if (::fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 07777) != 0700
        || ::fsync(parent) != 0) { ::close(fd); return -1; }
    return fd;
}
bool present(int directory)
{
    struct stat info{};
    return ::fstatat(directory, "source.json", &info, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT;
}
bool prefixes(const QJsonValue &value, QStringList &result)
{
    if (!value.isArray() || value.toArray().isEmpty() || value.toArray().size() > LinuxRouteSnapshotRows) return false;
    for (const auto &item : value.toArray()) {
        if (!item.isString() || !canonicalIpv4Prefix(item.toString())) return false;
        result.append(item.toString());
    }
    return true;
}
}

QByteArray linuxHelperSocketName(uid_t uid, const QUuid &owner)
{
    return QByteArray("JustConnect.network.") + QByteArray::number(uid) + '.' + owner.toByteArray(QUuid::WithoutBraces);
}

int connectLinuxHelper(uid_t uid, const QUuid &owner)
{
    if (uid == 0 || owner.isNull()) return -1;
    const int socket = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (socket < 0) return -1;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto name = linuxHelperSocketName(uid, owner);
    if (size_t(name.size()) < sizeof(address.sun_path)) {
        std::memcpy(address.sun_path + 1, name.constData(), size_t(name.size()));
        if (::connect(socket, reinterpret_cast<const sockaddr *>(&address), socklen_t(offsetof(sockaddr_un, sun_path) + 1 + name.size())) == 0) return socket;
    }
    ::close(socket);
    return -1;
}

Result sendLinuxHelperPacket(int socket, const QJsonObject &packet, int descriptor)
{
    const auto bytes = QJsonDocument(packet).toJson(QJsonDocument::Compact);
    if (bytes.size() > LinuxHelperPacketBytes) return invalid("Network helper packet exceeds its budget.");
    iovec data{const_cast<char *>(bytes.constData()), size_t(bytes.size())};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> control{};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    if (descriptor >= 0) {
        message.msg_control = control.data(); message.msg_controllen = control.size();
        auto *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    }
    QDeadlineTimer deadline(packetTimeoutMs);
    for (;;) {
        const auto size = ::sendmsg(socket, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (size == bytes.size()) return {};
        if (size < 0 && errno == EINTR && !deadline.hasExpired()) continue;
        if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && waitFor(socket, POLLOUT, deadline)) continue;
        return invalid("Cannot deliver a complete network helper packet.");
    }
}

Result receiveLinuxHelperPacket(int socket, QJsonObject &packet, int &descriptor, int timeoutMs)
{
    packet = {}; descriptor = -1;
    QDeadlineTimer deadline(timeoutMs);
    if (!waitFor(socket, POLLIN, deadline)) return invalid("Network helper channel ended or timed out.");
    QByteArray bytes(LinuxHelperPacketBytes, Qt::Uninitialized);
    iovec data{bytes.data(), size_t(bytes.size())};
    alignas(cmsghdr) std::array<char, CMSG_SPACE(16 * sizeof(int))> control{};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = control.data(); message.msg_controllen = control.size();
    ssize_t size;
    do { size = ::recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT); } while (size < 0 && errno == EINTR);
    QList<int> received;
    bool ancillaryValid = true;
    for (auto *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len < CMSG_LEN(0)) {
            ancillaryValid = false; continue;
        }
        const auto length = header->cmsg_len - CMSG_LEN(0);
        if (length % sizeof(int)) ancillaryValid = false;
        for (size_t offset = 0; offset + sizeof(int) <= length; offset += sizeof(int)) {
            int fd = -1; std::memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd)); received.append(fd);
        }
    }
    const auto close = qScopeGuard([&] { for (int fd : received) ::close(fd); });
    if (size <= 0 || size > bytes.size() || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || !ancillaryValid || received.size() > 1)
        return invalid("Network helper packet or descriptor framing is invalid.");
    bytes.resize(size);
    const auto document = QJsonDocument::fromJson(bytes);
    if (!document.isObject()) return invalid("Network helper packet must be a JSON object.");
    packet = document.object();
    if (!received.isEmpty()) descriptor = received.takeFirst();
    return {};
}

int runLinuxNetworkHelper(int socket, int trustedDirectory, uid_t uid, pid_t pid, const QUuid &owner)
{
    ucred peer{}; socklen_t size = sizeof(peer);
    int type = 0; socklen_t typeSize = sizeof(type);
    struct stat here{}, caller{}, base{};
    const auto callerNamespace = QByteArray("/proc/") + QByteArray::number(pid) + "/ns/net";
    if (::geteuid() != 0 || uid == 0 || pid <= 0 || owner.isNull()
        || ::getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &typeSize) != 0 || type != SOCK_SEQPACKET
        || ::getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 || size != sizeof(peer) || peer.uid != uid || peer.pid != pid
        || ::stat("/proc/thread-self/ns/net", &here) != 0 || ::stat(callerNamespace.constData(), &caller) != 0
        || here.st_dev != caller.st_dev || here.st_ino != caller.st_ino
        || ::fstat(trustedDirectory, &base) != 0 || !S_ISDIR(base.st_mode) || base.st_uid != 0 || (base.st_mode & 07777) != 0700)
        return 1;
    const int flags = ::fcntl(socket, F_GETFD);
    if (flags < 0 || ::fcntl(socket, F_SETFD, flags | FD_CLOEXEC) != 0) return 1;

    const auto id = owner.toString(QUuid::WithoutBraces);
    const auto requestValid = [&](const QJsonObject &request) {
        return request["version"] == LinuxHelperProtocol && request["owner"] == id && request["operation"].isString();
    };
    QJsonObject request; int supplied = -1;
    auto result = receiveLinuxHelperPacket(socket, request, supplied, handshakeTimeoutMs);
    if (supplied >= 0) { ::close(supplied); return 1; }
    if (!result.succeeded() || !requestValid(request)) return 1;
    const bool applying = request["operation"] == "apply";
    QStringList capturePrefixes, sourcePrefixes;
    const auto config = request.value("device").toObject(), underlay = request.value("underlay").toObject();
    if (applying) {
        if (!fields(request, {"version", "owner", "operation", "device", "capture", "underlay"})
            || !fields(config, {"source", "peer", "mtu"})
            || !UnixTunDevice::validIpv4Configuration(config["source"].toString(), config["peer"].toString(), config["mtu"].toInteger(-1))
            || !prefixes(request["capture"], capturePrefixes) || !fields(underlay, {"interface", "source", "gateway", "prefixes"})
            || !underlay["interface"].isString() || !canonicalUnicastIpv4(underlay["source"].toString())
            || !underlay["gateway"].isString() || (!underlay["gateway"].toString().isEmpty() && !canonicalUnicastIpv4(underlay["gateway"].toString()))
            || !prefixes(underlay["prefixes"], sourcePrefixes)) return 1;
    } else if (request["operation"] != "recover" || !fields(request, {"version", "owner", "operation"})) return 1;

    const auto name = QByteArray::number(uid) + '-' + owner.toByteArray(QUuid::WithoutBraces);
    // Recovery never creates an absent operation: absence is not a completion receipt.
    struct stat existing{};
    if (!applying && ::fstatat(trustedDirectory, name.constData(), &existing, AT_SYMLINK_NOFOLLOW) != 0) return 1;
    const int directory = privateDirectory(trustedDirectory, name);
    if (directory < 0) return 1;
    const auto closeDirectory = qScopeGuard([&] { ::close(directory); });
    LinuxSourceJournal metadata;
    if (!metadata.open(directory, owner).succeeded()) return 1;
    QJsonObject context;
    const auto contextValid = [&] {
        return fields(context, {"version", "owner", "uid", "namespace", "phase"})
            && context["version"] == LinuxHelperProtocol && context["owner"] == id && context["uid"].toInteger(-1) == uid
            && context["namespace"] == linuxNetworkNamespace()
            && (context["phase"] == "prepared" || context["phase"] == "active" || context["phase"] == "restored");
    };
    if (applying) {
        context = {{"version", LinuxHelperProtocol}, {"owner", id}, {"uid", qint64(uid)},
                   {"namespace", linuxNetworkNamespace()}, {"phase", "prepared"}};
        if (context["namespace"].toString().isEmpty() || !metadata.store(context).succeeded()) return 1;
    } else if (!metadata.load(context).succeeded() || !contextValid()) return 1;

    const int captureDirectory = privateDirectory(directory, "capture"), sourceDirectory = privateDirectory(directory, "underlay");
    const auto closeOperations = qScopeGuard([&] { if (captureDirectory >= 0) ::close(captureDirectory); if (sourceDirectory >= 0) ::close(sourceDirectory); });
    if (captureDirectory < 0 || sourceDirectory < 0) return 1;
    LinuxSourceJournal captureJournal, sourceJournal;
    if (!captureJournal.open(captureDirectory, owner).succeeded() || !sourceJournal.open(sourceDirectory, owner).succeeded()) return 1;
    if (context["phase"] == "restored" && (present(captureDirectory) || present(sourceDirectory))) return 1;
    const auto writer = [](LinuxSourceJournal &journal) {
        return [&journal](const QJsonObject &record) { return record.isEmpty() ? journal.remove() : journal.store(record); };
    };
    const auto captureWriter = writer(captureJournal), sourceWriter = writer(sourceJournal);
    UnixTunDevice device;
    LinuxTunRoutes capture;
    LinuxSourceRoutes source;
    const auto restore = [&]() -> Result {
        if (context["phase"] == "restored") return {};
        Result captureResult, sourceResult;
        if (!capture.snapshot().isEmpty()) captureResult = capture.restore(device, captureWriter);
        else if (present(captureDirectory)) {
            QJsonObject saved;
            captureResult = captureJournal.load(saved);
            if (captureResult.succeeded()) captureResult = capture.recover(owner, saved, captureWriter);
        }
        // Keep original egress until capture is confirmed released.
        if (!captureResult.succeeded()) return captureResult;
        if (!source.snapshot().isEmpty()) sourceResult = source.restore(owner, sourceWriter);
        else if (present(sourceDirectory)) {
            QJsonObject saved;
            sourceResult = sourceJournal.load(saved);
            if (sourceResult.succeeded()) sourceResult = source.recover(owner, saved, sourceWriter);
        }
        if (!sourceResult.succeeded()) return sourceResult;
        device.close();
        context["phase"] = "restored";
        const auto saved = metadata.store(context);
        if (!saved.succeeded()) { context["phase"] = "active"; return saved; }
        return {};
    };
    if (applying) {
        result = source.apply(owner, underlay["interface"].toString(), underlay["source"].toString(), underlay["gateway"].toString(), sourcePrefixes, sourceWriter);
        if (result.succeeded()) result = device.createIpv4(owner, config["source"].toString(), config["peer"].toString(), config["mtu"].toInt());
        if (result.succeeded()) result = capture.apply(device, config["source"].toString(), config["peer"].toString(), capturePrefixes, captureWriter);
        if (result.succeeded()) { context["phase"] = "active"; result = metadata.store(context); }
        if (!result.succeeded()) {
            const auto rolledBack = restore();
            if (!rolledBack.succeeded()) result = rolledBack;
        }
    } else result = restore();
    const auto reply = [&](const Result &operation, bool withDevice) {
        QJsonObject response{{"version", LinuxHelperProtocol}, {"owner", id}, {"status", int(operation.status)},
            {"detail", operation.detail}, {"changed", operation.mayHaveChanged}, {"state", context["phase"]},
            {"device", withDevice ? device.snapshot() : QJsonObject{}}};
        return sendLinuxHelperPacket(socket, response, withDevice ? device.descriptor() : -1);
    };
    if (!reply(result, applying && result.succeeded()).succeeded()) return restore().succeeded() ? 0 : 1;
    if (!result.succeeded() && context["phase"] != "restored") return 1;
    if (context["phase"] == "active") {
        request = {}; supplied = -1;
        const auto received = receiveLinuxHelperPacket(socket, request, supplied, -1);
        if (supplied >= 0) ::close(supplied);
        const bool valid = received.succeeded() && supplied < 0 && requestValid(request)
            && request["operation"] == "restore" && fields(request, {"version", "owner", "operation"});
        result = restore();
        if (!valid || !result.succeeded()) { if (valid) reply(result, false); return result.succeeded() ? 0 : 1; }
        if (!reply(result, false).succeeded()) return 0;
    }
    // Keep a durable completion receipt until this peer acknowledges the restored state.
    request = {}; supplied = -1;
    const auto acknowledged = receiveLinuxHelperPacket(socket, request, supplied, packetTimeoutMs);
    if (supplied >= 0) ::close(supplied);
    if (acknowledged.succeeded() && supplied < 0 && requestValid(request)
        && request["operation"] == "acknowledge" && fields(request, {"version", "owner", "operation"})) {
        captureJournal.close(); sourceJournal.close();
        if (::unlinkat(directory, "capture", AT_REMOVEDIR) != 0 || ::unlinkat(directory, "underlay", AT_REMOVEDIR) != 0
            || ::fsync(directory) != 0 || !metadata.remove().succeeded()) return 1;
        metadata.close();
        if (::unlinkat(trustedDirectory, name.constData(), AT_REMOVEDIR) != 0 || ::fsync(trustedDirectory) != 0) return 1;
    }
    return 0;
}
