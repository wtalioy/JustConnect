#include "networkhelper.h"
#include "sourcejournal.h"
#include "sourceroutes.h"
#include "tunroutes.h"
#include "tundns.h"
#include "networkhelperpaths.h"
#include "trustedexecutable.h"
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QScopeGuard>
#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr int handshakeTimeoutMs = 30000;
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

struct OwnedOperation {
    OwnedOperation(int parent, uid_t uid, const QUuid &owner)
        : parent(parent), uid(uid), owner(owner), id(owner.toString(QUuid::WithoutBraces)),
          name(QByteArray::number(uid) + '-' + owner.toByteArray(QUuid::WithoutBraces)) {}
    ~OwnedOperation()
    {
        for (int fd : {dnsDirectory, captureDirectory, sourceDirectory, directory}) if (fd >= 0) ::close(fd);
    }
    Result open(bool applying, bool cleaning, bool *alreadyOwned = nullptr)
    {
        if (alreadyOwned) *alreadyOwned = false;
        struct stat base{}, existing{};
        if (::geteuid() != 0 || uid == 0 || owner.isNull() || ::fstat(parent, &base) != 0
            || !S_ISDIR(base.st_mode) || base.st_uid != 0 || (base.st_mode & 07777) != 0700)
            return invalid("A trusted private root directory and connection owner are required.");
        if (!applying && ::fstatat(parent, name.constData(), &existing, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) { cleaned = true; return {}; }
            return invalid("Recovery ownership is absent or inaccessible.");
        }
        directory = privateDirectory(parent, name);
        if (directory < 0) return invalid("Cannot open the private connection directory.");
        const auto opened = metadata.open(directory, owner, alreadyOwned);
        if (!opened.succeeded()) return opened;
        const auto scope = linuxNetworkNamespace();
        if (scope.isEmpty()) return invalid("Cannot bind recovery to the current network namespace.");
        if (applying) {
            context = {{"version", LinuxHelperStorageVersion}, {"owner", id}, {"uid", qint64(uid)},
                {"namespace", scope}, {"phase", "prepared"}};
            const auto saved = metadata.store(context);
            if (!saved.succeeded()) return saved;
        } else {
            // A crash after durable metadata removal can leave only the locked, empty receipt directory.
            if (cleaning && !present(directory)) {
                if (::unlinkat(parent, name.constData(), AT_REMOVEDIR) != 0 || ::fsync(parent) != 0)
                    return invalid("Cannot remove the empty private receipt directory.");
                cleaned = changed = true; return {};
            }
            const auto loaded = metadata.load(context);
            if (!loaded.succeeded()) return loaded;
            if (!fields(context, {"version", "owner", "uid", "namespace", "phase"})
                || (context["version"] != LinuxHelperStorageVersion && context["version"] != 1)
                || context["owner"] != id || context["uid"].toInteger(-1) != uid
                || context["namespace"] != scope
                || (context["phase"] != "prepared" && context["phase"] != "active" && context["phase"] != "restored"))
                return invalid("Recovery context does not match its privileged owner and current namespace.");
        }
        if (cleaning && context["phase"] != "restored") return invalid("An active connection cannot be cleaned as a receipt.");
        captureDirectory = privateDirectory(directory, "capture");
        sourceDirectory = privateDirectory(directory, "underlay");
        if (captureDirectory < 0 || sourceDirectory < 0) return invalid("Cannot open the private operation journals.");
        const auto captureOpened = captureJournal.open(captureDirectory, owner);
        if (!captureOpened.succeeded()) return captureOpened;
        const auto sourceOpened = sourceJournal.open(sourceDirectory, owner);
        if (!sourceOpened.succeeded()) return sourceOpened;
        if (context["version"] == 1) {
            struct stat unexpected{};
            if (::fstatat(directory, "dns", &unexpected, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
                return invalid("Legacy recovery metadata cannot own DNS operations.");
        } else {
            dnsDirectory = privateDirectory(directory, "dns");
            if (dnsDirectory < 0) return invalid("Cannot open the private DNS journal.");
            const auto dnsOpened = dnsJournal.open(dnsDirectory, owner);
            if (!dnsOpened.succeeded()) return dnsOpened;
        }
        if (context["phase"] == "restored" && (present(captureDirectory) || present(sourceDirectory)
            || (dnsDirectory >= 0 && present(dnsDirectory))))
            return invalid("A completed receipt still has operation journals.");
        return {};
    }
    Result apply(const LinuxHelperConfiguration &config)
    {
        auto result = source.apply(owner, config.originalInterface, config.originalSource, config.originalGateway,
            config.originalPrefixes, writer(sourceJournal));
        if (result.succeeded()) result = device.createIpv4(owner, config.address, config.peer, config.mtu);
        if (result.succeeded()) result = capture.apply(device, config.address, config.peer, config.capturePrefixes, writer(captureJournal));
        if (result.succeeded() && !config.dnsDomains.isEmpty()) result = dns.apply(device, config.dnsDomains, writer(dnsJournal));
        if (result.succeeded()) { context["phase"] = "active"; result = metadata.store(context); }
        if (!result.succeeded()) {
            const auto rolledBack = restore();
            if (!rolledBack.succeeded()) result = rolledBack;
        }
        return result;
    }
    Result extend(const QStringList &addresses)
    {
        if (context["phase"] != "active") return invalid("DNS routes require active connection ownership.");
        auto result = source.extend(owner,addresses,writer(sourceJournal));
        bool changed = result.mayHaveChanged;
        if (result.succeeded()) result = capture.extend(device,addresses,writer(captureJournal));
        if (result.succeeded()) return {Status::Success,{},changed || result.mayHaveChanged};
        const auto restored = restore();
        if (!restored.succeeded()) result = restored;
        result.mayHaveChanged = true;
        return result;
    }
    Result reconcile(const QStringList &prefixes)
    {
        if (context["phase"] != "active") return invalid("Route changes require active connection ownership.");
        // Original egress remains owned until full restoration, including existing relay traffic.
        auto result = source.ensurePrefixes(owner,prefixes,writer(sourceJournal));
        const bool changed = result.mayHaveChanged;
        if (result.succeeded()) result = capture.reconcile(device,prefixes,writer(captureJournal));
        if (result.succeeded()) return {Status::Success,{},changed || result.mayHaveChanged};
        const auto restored = restore();
        if (!restored.succeeded()) result = restored;
        result.mayHaveChanged = true;
        return result;
    }
    Result restore()
    {
        if (context["phase"] == "restored") return {};
        Result dnsResult;
        if (!dns.snapshot().isEmpty()) dnsResult = dns.restore(device, writer(dnsJournal));
        else if (dnsDirectory >= 0 && present(dnsDirectory)) {
            QJsonObject saved;
            dnsResult = dnsJournal.load(saved);
            if (dnsResult.succeeded()) dnsResult = dns.recover(owner, saved, writer(dnsJournal));
        }
        if (!dnsResult.succeeded()) return dnsResult;
        Result captureResult, sourceResult;
        if (!capture.snapshot().isEmpty()) captureResult = capture.restore(device, writer(captureJournal));
        else if (present(captureDirectory)) {
            QJsonObject saved;
            captureResult = captureJournal.load(saved);
            if (captureResult.succeeded()) captureResult = capture.recover(owner, saved, writer(captureJournal));
        }
        // Keep original egress until capture is confirmed released.
        if (!captureResult.succeeded()) return captureResult;
        if (!source.snapshot().isEmpty()) sourceResult = source.restore(owner, writer(sourceJournal));
        else if (present(sourceDirectory)) {
            QJsonObject saved;
            sourceResult = sourceJournal.load(saved);
            if (sourceResult.succeeded()) sourceResult = source.recover(owner, saved, writer(sourceJournal));
        }
        if (!sourceResult.succeeded()) return sourceResult;
        device.close();
        context["phase"] = "restored";
        const auto saved = metadata.store(context);
        if (!saved.succeeded()) { context["phase"] = "active"; return saved; }
        return {};
    }
    bool removeReceipt()
    {
        dnsJournal.close(); captureJournal.close(); sourceJournal.close();
        if ((dnsDirectory >= 0 && ::unlinkat(directory, "dns", AT_REMOVEDIR) != 0)
            || ::unlinkat(directory, "capture", AT_REMOVEDIR) != 0 || ::unlinkat(directory, "underlay", AT_REMOVEDIR) != 0
            || ::fsync(directory) != 0 || !metadata.remove().succeeded()) return false;
        metadata.close();
        return ::unlinkat(parent, name.constData(), AT_REMOVEDIR) == 0 && ::fsync(parent) == 0;
    }
    QJsonObject context;
    UnixTunDevice device;
    bool cleaned = false, changed = false;
private:
    static LinuxSourceRoutes::CheckpointWriter writer(LinuxSourceJournal &journal)
    {
        return [&journal](const QJsonObject &record) { return record.isEmpty() ? journal.remove() : journal.store(record); };
    }
    int parent, directory = -1, captureDirectory = -1, sourceDirectory = -1, dnsDirectory = -1;
    uid_t uid;
    QUuid owner;
    QString id;
    QByteArray name;
    LinuxSourceJournal metadata, captureJournal, sourceJournal, dnsJournal;
    LinuxTunRoutes capture;
    LinuxSourceRoutes source;
    LinuxTunDns dns{QDBusConnection::connectToBus(QStringLiteral("unix:path=/run/dbus/system_bus_socket"),
                                               QStringLiteral("JustConnect.network-helper.dns"))};
};
}

QJsonObject LinuxHelperRecoverySummary::json() const
{
    return {{"worker", "network-recovery"}, {"capacity", LinuxHelperRecoveryEntries}, {"checked", checked}, {"live", live}, {"restored", restored},
        {"unchanged", unchanged}, {"failed", failed}, {"limited", limited}};
}

LinuxHelperRecoverySummary recoverLinuxHelperRecords(int trustedDirectory)
{
    LinuxHelperRecoverySummary summary;
    struct stat base{};
    if (::geteuid() != 0 || ::fstat(trustedDirectory, &base) != 0 || !S_ISDIR(base.st_mode)
        || base.st_uid != 0 || (base.st_mode & 07777) != 0700) { ++summary.failed; return summary; }
    const int descriptor = ::openat(trustedDirectory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    DIR *entries = descriptor >= 0 ? ::fdopendir(descriptor) : nullptr;
    if (!entries) { if (descriptor >= 0) ::close(descriptor); ++summary.failed; return summary; }
    const auto close = qScopeGuard([&] { ::closedir(entries); });
    for (;;) {
        errno = 0;
        const auto *entry = ::readdir(entries);
        if (!entry) { if (errno) ++summary.failed; break; }
        const QByteArray name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (summary.checked == LinuxHelperRecoveryEntries) { summary.limited = true; break; }
        ++summary.checked;
        const auto separator = name.indexOf('-');
        const auto account = QString::fromLatin1(name.first(separator < 0 ? 0 : separator));
        bool validUid = false;
        const auto uid = account.toUInt(&validUid);
        const auto connection = QString::fromLatin1(name.mid(separator + 1));
        const QUuid owner(connection);
        if (!validUid || uid == 0 || QString::number(uid) != account || owner.isNull()
            || owner.toString(QUuid::WithoutBraces) != connection) { ++summary.failed; continue; }
        OwnedOperation operation(trustedDirectory, uid, owner);
        bool live = false;
        const auto opened = operation.open(false, false, &live);
        if (live) { ++summary.live; continue; }
        if (!opened.succeeded()) { ++summary.failed; continue; }
        if (operation.context["phase"] == "restored") { ++summary.unchanged; continue; }
        if (operation.restore().succeeded()) ++summary.restored;
        else ++summary.failed;
    }
    return summary;
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

QJsonObject linuxHelperApplyRequest(const QUuid &owner, const LinuxHelperConfiguration &config)
{
    return {{"version", LinuxHelperProtocol}, {"owner", owner.toString(QUuid::WithoutBraces)}, {"operation", "apply"},
        {"device", QJsonObject{{"source", config.address}, {"peer", config.peer}, {"mtu", config.mtu}}},
        {"capture", QJsonArray::fromStringList(config.capturePrefixes)},
        {"dns", QJsonArray::fromStringList(config.dnsDomains)},
        {"underlay", QJsonObject{{"interface", config.originalInterface}, {"source", config.originalSource},
            {"gateway", config.originalGateway}, {"prefixes", QJsonArray::fromStringList(config.originalPrefixes)}}}};
}

std::optional<LinuxHelperConfiguration> parseLinuxHelperApply(const QUuid &owner, const QJsonObject &request)
{
    const auto device = request["device"].toObject(), original = request["underlay"].toObject();
    LinuxHelperConfiguration config;
    if (owner.isNull() || request["owner"] != owner.toString(QUuid::WithoutBraces) || request["version"] != LinuxHelperProtocol
        || request["operation"] != "apply" || !fields(request, {"version", "owner", "operation", "device", "capture", "underlay", "dns"})
        || QJsonDocument(request).toJson(QJsonDocument::Compact).size() > LinuxHelperPacketBytes
        || !fields(device, {"source", "peer", "mtu"})
        || !UnixTunDevice::validIpv4Configuration(device["source"].toString(), device["peer"].toString(), device["mtu"].toInteger(-1))
        || !prefixes(request["capture"], config.capturePrefixes)
        || !fields(original, {"interface", "source", "gateway", "prefixes"}) || !original["interface"].isString()
        || !original["gateway"].isString() || !prefixes(original["prefixes"], config.originalPrefixes)
        || !request["dns"].isArray() || request["dns"].toArray().size() > LinuxRouteSnapshotRows) return {};
    for (const auto &name : request["dns"].toArray()) {
        if (!name.isString()) return {};
        config.dnsDomains.append(name.toString());
    }
    if (!config.dnsDomains.isEmpty() && !LinuxTunDns::validDomains(config.dnsDomains)) return {};
    config.address = device["source"].toString(); config.peer = device["peer"].toString(); config.mtu = device["mtu"].toInt();
    config.originalInterface = original["interface"].toString(); config.originalSource = original["source"].toString();
    config.originalGateway = original["gateway"].toString();
    if (!LinuxSourceRoutes::validate(config.originalInterface, config.originalSource, config.originalGateway, config.originalPrefixes).succeeded()) return {};
    return config;
}

QJsonObject linuxHelperExtendRequest(const QUuid &owner, const QStringList &addresses)
{
    return {{"version",LinuxHelperProtocol},{"owner",owner.toString(QUuid::WithoutBraces)},
        {"operation","extend"},{"addresses",QJsonArray::fromStringList(addresses)}};
}

std::optional<QStringList> parseLinuxHelperExtend(const QUuid &owner, const QJsonObject &request)
{
    if (owner.isNull() || request["version"] != LinuxHelperProtocol || request["owner"] != owner.toString(QUuid::WithoutBraces)
        || request["operation"] != "extend" || !fields(request,{"version","owner","operation","addresses"})
        || !request["addresses"].isArray() || request["addresses"].toArray().isEmpty()
        || request["addresses"].toArray().size() > LinuxRouteSnapshotRows
        || QJsonDocument(request).toJson(QJsonDocument::Compact).size() > LinuxHelperPacketBytes) return {};
    QStringList addresses;
    for (const auto &address : request["addresses"].toArray()) {
        if (!address.isString() || !canonicalUnicastIpv4(address.toString())) return {};
        addresses.append(address.toString());
    }
    addresses.removeDuplicates();
    return addresses;
}

QJsonObject linuxHelperRoutesRequest(const QUuid &owner, const QStringList &prefixes)
{
    return {{"version",LinuxHelperProtocol},{"owner",owner.toString(QUuid::WithoutBraces)},
        {"operation","routes"},{"prefixes",QJsonArray::fromStringList(prefixes)}};
}

std::optional<QStringList> parseLinuxHelperRoutes(const QUuid &owner, const QJsonObject &request)
{
    if (owner.isNull() || request["version"] != LinuxHelperProtocol || request["owner"] != owner.toString(QUuid::WithoutBraces)
        || request["operation"] != "routes" || !fields(request,{"version","owner","operation","prefixes"})
        || !request["prefixes"].isArray() || request["prefixes"].toArray().size() > LinuxRouteSnapshotRows
        || QJsonDocument(request).toJson(QJsonDocument::Compact).size() > LinuxHelperPacketBytes) return {};
    QStringList result;
    for (const auto &prefix : request["prefixes"].toArray()) {
        if (!prefix.isString() || !canonicalIpv4Prefix(prefix.toString())) return {};
        result.append(prefix.toString());
    }
    result.removeDuplicates();
    return result;
}

Result sendLinuxHelperPacket(int socket, const QJsonObject &packet, int descriptor, int timeoutMs)
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
    QDeadlineTimer deadline(timeoutMs);
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

PlatformOperationResult linuxNetworkRecoveryReady()
{
    const auto unavailable = [] { return Result{Status::Unsupported, "Enable the installed system network recovery timer before connecting."}; };
    if (!trustedLinuxExecutable(LinuxNetworkHelperSystemctlPath)) return unavailable();
    const QString timer = QString::fromLatin1(LinuxNetworkHelperRecoveryUnit) + ".timer";
    const QString service = QString::fromLatin1(LinuxNetworkHelperRecoveryUnit) + ".service";
    QProcessEnvironment environment;
    environment.insert("LC_ALL", "C");
    const auto inspected = runPlatformCommand(QString::fromLatin1(LinuxNetworkHelperSystemctlPath),
        {"--no-ask-password", "show", "--property=Id,ActiveState,Unit,Type,User,PrivateNetwork,NetworkNamespacePath,Slice,RemainAfterExit", timer, service},
        LinuxRouteOperationTimeoutMs, {}, environment);
    if (!inspected.result.succeeded()) return unavailable();
    QMap<QString, QMap<QString, QString>> units;
    for (const auto &block : inspected.output.split("\n\n", Qt::SkipEmptyParts)) {
        QMap<QString, QString> properties;
        for (const auto &line : block.split('\n', Qt::SkipEmptyParts)) {
            const auto separator = line.indexOf('=');
            if (separator <= 0 || properties.contains(line.first(separator))) return unavailable();
            properties.insert(line.first(separator), line.mid(separator + 1));
        }
        const auto id = properties.value("Id");
        if (units.contains(id)) return unavailable();
        units.insert(id, properties);
    }
    const auto schedule = units.value(timer), worker = units.value(service);
    if (units.size() != 2 || schedule.value("ActiveState") != "active" || schedule.value("Unit") != service
        || worker.value("Type") != "oneshot" || worker.value("User") != "root" || worker.value("PrivateNetwork") != "no"
        || worker.value("Slice") != "system.slice" || worker.value("RemainAfterExit") != "no") return unavailable();
    const auto scope = worker.value("NetworkNamespacePath");
    const auto path = scope.isEmpty() ? QByteArray("/proc/1/ns/net") : scope.toLocal8Bit();
    if (!sameLinuxNetworkNamespace(path))
        return {Status::Unsupported, "The system recovery service does not share this network namespace."};
    return {};
}

int runLinuxNetworkHelper(int socket, int trustedDirectory, uid_t uid, pid_t pid, const QUuid &owner,
                         const std::function<Result()> &beforeApply)
{
    ucred peer{}; socklen_t size = sizeof(peer);
    int type = 0; socklen_t typeSize = sizeof(type);
    struct stat base{};
    const auto callerNamespace = QByteArray("/proc/") + QByteArray::number(pid) + "/ns/net";
    if (::geteuid() != 0 || uid == 0 || pid <= 0 || owner.isNull()
        || ::getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &typeSize) != 0 || type != SOCK_SEQPACKET
        || ::getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 || size != sizeof(peer) || peer.uid != uid || peer.pid != pid
        || !sameLinuxNetworkNamespace(callerNamespace)
        || ::fstat(trustedDirectory, &base) != 0 || !S_ISDIR(base.st_mode) || base.st_uid != 0 || (base.st_mode & 07777) != 0700)
        return 1;
    const int flags = ::fcntl(socket, F_GETFD);
    if (flags < 0 || ::fcntl(socket, F_SETFD, flags | FD_CLOEXEC) != 0) return 1;

    const auto id = owner.toString(QUuid::WithoutBraces);
    const auto requestValid = [&](const QJsonObject &request) {
        return request["version"] == LinuxHelperProtocol && request["owner"] == id && request["operation"].isString();
    };
    const auto cleaned = [&](bool changed) {
        return sendLinuxHelperPacket(socket, {{"version", LinuxHelperProtocol}, {"owner", id}, {"status", int(Status::Success)},
            {"detail", QString{}}, {"changed", changed}, {"state", "cleaned"}, {"device", QJsonObject{}}}).succeeded() ? 0 : 1;
    };
    QJsonObject request; int supplied = -1;
    auto result = receiveLinuxHelperPacket(socket, request, supplied, handshakeTimeoutMs);
    if (supplied >= 0) { ::close(supplied); return 1; }
    if (!result.succeeded() || !requestValid(request)) return 1;
    const bool applying = request["operation"] == "apply";
    const bool cleaning = request["operation"] == "cleanup";
    std::optional<LinuxHelperConfiguration> config;
    if (applying) {
        config = parseLinuxHelperApply(owner, request);
        if (!config) return 1;
    } else if ((!cleaning && request["operation"] != "recover") || !fields(request, {"version", "owner", "operation"})) return 1;

    OwnedOperation operation(trustedDirectory, uid, owner);
    result = operation.open(applying, cleaning);
    if (!result.succeeded()) return 1;
    if (operation.cleaned) return cleaned(operation.changed);
    if (cleaning) {
        if (!operation.removeReceipt()) return 1;
        return cleaned(true);
    }
    if (applying && beforeApply) result = beforeApply();
    if (result.succeeded()) result = applying ? operation.apply(*config) : operation.restore();
    else {
        const auto restored = operation.restore();
        if (!restored.succeeded()) result = restored;
    }
    const auto reply = [&](const Result &returned, bool withDevice) {
        QJsonObject response{{"version", LinuxHelperProtocol}, {"owner", id}, {"status", int(returned.status)},
            {"detail", returned.detail}, {"changed", returned.mayHaveChanged}, {"state", operation.context["phase"]},
            {"device", withDevice ? operation.device.snapshot() : QJsonObject{}}};
        return sendLinuxHelperPacket(socket, response, withDevice ? operation.device.descriptor() : -1);
    };
    if (!reply(result, applying && result.succeeded()).succeeded()) return operation.restore().succeeded() ? LinuxHelperReceiptRetained : 1;
    if (!result.succeeded() && operation.context["phase"] != "restored") return 1;
    while (operation.context["phase"] == "active") {
        request = {}; supplied = -1;
        const auto received = receiveLinuxHelperPacket(socket, request, supplied, -1);
        if (supplied >= 0) ::close(supplied);
        const bool authenticated = received.succeeded() && supplied < 0 && requestValid(request)
            && sameLinuxNetworkNamespace(callerNamespace);
        const bool changingRoutes = request["operation"] == "routes";
        if (authenticated && (request["operation"] == "extend" || changingRoutes)) {
            const auto targets = changingRoutes ? parseLinuxHelperRoutes(owner,request) : parseLinuxHelperExtend(owner,request);
            if (targets) {
                result = beforeApply ? beforeApply() : Result{};
                if (result.succeeded()) result = changingRoutes ? operation.reconcile(*targets) : operation.extend(*targets);
                else {
                    const auto restored = operation.restore();
                    if (!restored.succeeded()) result = restored;
                    result.mayHaveChanged = true;
                }
                if (!reply(result,false).succeeded()) return operation.restore().succeeded() ? LinuxHelperReceiptRetained : 1;
                if (!result.succeeded() && operation.context["phase"] != "restored") return 1;
                continue;
            }
        }
        const bool valid = authenticated && request["operation"] == "restore" && fields(request, {"version", "owner", "operation"});
        result = operation.restore();
        if (!valid || !result.succeeded()) { if (valid) reply(result, false); return result.succeeded() ? LinuxHelperReceiptRetained : 1; }
        if (!reply(result, false).succeeded()) return LinuxHelperReceiptRetained;
    }
    // Keep a durable completion receipt until this peer acknowledges the restored state.
    request = {}; supplied = -1;
    const auto acknowledged = receiveLinuxHelperPacket(socket, request, supplied, LinuxHelperPacketTimeoutMs);
    if (supplied >= 0) ::close(supplied);
    if (acknowledged.succeeded() && supplied < 0 && requestValid(request)
        && request["operation"] == "acknowledge" && fields(request, {"version", "owner", "operation"})) {
        return operation.removeReceipt() ? 0 : 1;
    }
    return LinuxHelperReceiptRetained;
}
