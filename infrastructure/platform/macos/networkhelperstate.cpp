#include "networkhelperstate.h"
#include "infrastructure/platform/ipv4.h"
#include <QScopeGuard>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result failed(const char *message, bool changed = true) { return {Status::Failed,QString::fromLatin1(message),changed}; }
bool exists(int parent, const char *name)
{
    struct stat info{};
    return ::fstatat(parent,name,&info,AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT;
}
bool emptyDirectory(int directory)
{
    const int descriptor = ::openat(directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (descriptor < 0) return false;
    auto *stream = ::fdopendir(descriptor);
    if (!stream) { ::close(descriptor); return false; }
    bool empty = true; errno = 0;
    while (auto *entry = ::readdir(stream)) if (QByteArray(entry->d_name) != "." && QByteArray(entry->d_name) != "..") { empty = false; break; }
    const bool complete = errno == 0; ::closedir(stream); return empty && complete;
}
}

int openMacHelperBootDirectory()
{
    int parent = ::open("/var/db",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (parent < 0) return -1;
    const auto parts = QString::fromLatin1(MacHelperStatePath).mid(QStringLiteral("/var/db/").size()).split('/');
    const auto boot = macBootSession();
    if (boot.isEmpty()) { ::close(parent); return -1; }
    for (const auto &part : parts+QStringList{boot}) {
        const int child = openPrivateNetworkDirectory(parent,part.toLatin1());
        ::close(parent); if (child < 0) return -1; parent = child;
    }
    return parent;
}
MacNetworkHelperState::~MacNetworkHelperState()
{
    dns.restore();
    device.close(); captureJournal.close(); guardian.close();
    if (captureDirectory >= 0) ::close(captureDirectory);
    if (directory >= 0) ::close(directory);
    if (userDirectory >= 0) ::close(userDirectory);
}
bool MacNetworkHelperState::valid(const QJsonObject &record) const
{
    if (record.size() != 6 || record["version"] != MacHelperStorageVersion || record["owner"] != connection.toString(QUuid::WithoutBraces)
        || record["uid"].toDouble(-1) != double(user) || record["boot"] != macBootSession() || !record["device"].isObject()) return false;
    const auto phase = record["phase"].toString();
    if (phase != "preparing" && phase != "active" && phase != "restored") return false;
    const auto info = record["device"].toObject();
    if (info.isEmpty()) return phase != "active";
    const auto name = info["interface"].toString(); const auto index = info["index"].toInteger();
    const auto address = info["configuration"].toObject()["applied"].toObject()["ipv4"].toArray();
    if (info.size() != 4 || info["owner"] != record["owner"] || !name.startsWith("utun") || name.size() <= 4 || name.size() >= IFNAMSIZ
        || index <= 0 || index > 65535 || address.size() != 1) return false;
    for (const auto character : name.mid(4)) if (character < '0' || character > '9') return false;
    const auto pair = address.first().toObject();
    return canonicalUnicastIpv4(pair["source"].toString()) && canonicalUnicastIpv4(pair["peer"].toString()) && pair["source"] != pair["peer"];
}
Result MacNetworkHelperState::open(int bootDirectory, uid_t uid, const QUuid &owner, bool create)
{
    if (::geteuid() != 0 || !uid || owner.isNull() || directory >= 0) return failed("Invalid privileged connection owner.",false);
    user = uid; connection = owner;
    userDirectory = openPrivateNetworkDirectory(bootDirectory,QByteArray::number(uid),create);
    if (userDirectory < 0) return failed("Cannot open trusted account ownership storage.");
    const auto name = owner.toString(QUuid::WithoutBraces).toLatin1();
    if (create && ::mkdirat(userDirectory,name.constData(),0700) != 0) return failed("Existing connection ownership is preserved.");
    directory = openPrivateNetworkDirectory(userDirectory,name,false);
    if (directory < 0) return failed("Cannot open trusted connection storage.");
    auto result = guardian.open(directory,owner);
    if (!result.succeeded()) return result;
    if (create) {
        metadata = {{"version",MacHelperStorageVersion},{"owner",owner.toString(QUuid::WithoutBraces)},{"uid",qint64(uid)},
            {"boot",macBootSession()},{"phase","preparing"},{"device",QJsonObject{}}};
        return commit(metadata);
    }
    QJsonObject saved;
    result = guardian.load(saved);
    if (!result.succeeded() || !valid(saved)) return failed("Missing, corrupt or foreign connection ownership is preserved.");
    metadata = saved; return {};
}
Result MacNetworkHelperState::store(const QString &phase)
{
    auto next = metadata; next["phase"] = phase;
    return commit(next);
}
Result MacNetworkHelperState::commit(const QJsonObject &record)
{
    const auto result = guardian.store(record);
    if (result.succeeded()) metadata = record;
    else {
        QJsonObject accepted;
        if (guardian.load(accepted).succeeded() && valid(accepted)) metadata = accepted;
    }
    return result;
}
Result MacNetworkHelperState::apply(const MacHelperConfiguration &configuration)
{
    if (phase() != "preparing" || !metadata["device"].toObject().isEmpty()) return failed("Connection ownership is already active.");
    auto result = device.createIpv4(connection,configuration.address,configuration.peer,configuration.mtu);
    if (result.succeeded()) {
        auto next = metadata; next["device"] = device.snapshot(); result = commit(next);
    }
    if (result.succeeded()) {
        captureDirectory = openPrivateNetworkDirectory(directory,"capture");
        if (captureDirectory < 0) result = failed("Cannot prepare protected capture ownership.");
        else result = captureJournal.open(captureDirectory,connection);
    }
    if (result.succeeded()) result = capture.apply(device,configuration.capturePrefixes,[&](const QJsonObject &record) {
        return record.isEmpty() ? captureJournal.remove() : captureJournal.store(record);
    });
    if (result.succeeded() && !configuration.dnsDomains.isEmpty()) result = dns.apply(device,configuration.dnsDomains);
    if (result.succeeded()) result = store("active");
    if (result.succeeded()) {
        const int flags = ::fcntl(device.descriptor(),F_GETFL);
        if (flags < 0 || ::fcntl(device.descriptor(),F_SETFL,flags|O_NONBLOCK) != 0) result = failed("Cannot prepare nonblocking packet I/O.");
    }
    if (!result.succeeded()) {
        // No fd has been delivered; releasing this private reference removes the new device.
        dns.restore(); device.close(); const auto recovered = restore();
        result.mayHaveChanged = !recovered.succeeded();
        if (!recovered.succeeded()) result.detail += " Recovery: "+recovered.detail;
    }
    return result;
}
bool MacNetworkHelperState::deviceAbsent() const
{
    const auto info = metadata["device"].toObject();
    if (info.isEmpty()) return phase() == "preparing";
    char name[IFNAMSIZ]{};
    return !::if_nametoindex(info["interface"].toString().toLatin1().constData())
        && !::if_indextoname(quint32(info["index"].toInteger()),name);
}
Result MacNetworkHelperState::restore()
{
    // The live SC session independently proves DNS ownership, even if disk metadata was changed.
    dns.restore();
    QJsonObject checked;
    if (!guardian.load(checked).succeeded() || !valid(checked) || checked != metadata) {
        device.close(); return failed("Connection ownership changed; recovery responsibility is retained.");
    }
    if (phase() == "restored") { device.close(); return {}; }
    if (captureDirectory < 0 && exists(directory,"capture")) {
        captureDirectory = openPrivateNetworkDirectory(directory,"capture",false);
        if (captureDirectory < 0 || !captureJournal.open(captureDirectory,connection).succeeded()) { device.close(); return failed("Cannot authenticate capture recovery storage."); }
    }
    Result result;
    if (captureDirectory >= 0 && exists(captureDirectory,"source.json")) {
        QJsonObject saved; result = captureJournal.load(saved);
        const auto info = metadata["device"].toObject();
        const auto addresses = info["configuration"].toObject()["applied"].toObject()["ipv4"].toArray();
        const auto pair = addresses.size() == 1 ? addresses.first().toObject() : QJsonObject{};
        if (!result.succeeded() || addresses.size() != 1 || saved["owner"] != metadata["owner"] || saved["interface"] != info["interface"] || saved["index"] != info["index"]
            || saved["source"] != pair["source"] || saved["peer"] != pair["peer"]) result = failed("Saved capture scope does not match its connection.");
        else {
            const auto checkpoint = [&](const QJsonObject &record) { return record.isEmpty() ? captureJournal.remove() : captureJournal.store(record); };
            result = capture.snapshot().isEmpty() ? capture.recover(connection,saved,checkpoint) : capture.restore(connection,checkpoint);
        }
    } else if (!deviceAbsent()) result = failed("Capture ownership is absent while its device remains; responsibility is retained.");
    if (result.succeeded()) result = store("restored");
    device.close();
    if (!result.succeeded()) result.mayHaveChanged = true;
    return result;
}
Result MacNetworkHelperState::cleanup()
{
    if (phase() != "restored") {
        // Explicit cleanup may remove an empty receipt directory; it never claims network recovery.
        if (directory < 0 || device.descriptor() >= 0 || !emptyDirectory(directory)) return failed("Active or unknown ownership cannot be cleaned.");
        return removeDirectory();
    }
    if (exists(directory,"capture")) {
        captureJournal.close();
        if (captureDirectory >= 0) { ::close(captureDirectory); captureDirectory = -1; }
        if (::unlinkat(directory,"capture",AT_REMOVEDIR) != 0) return failed("Unknown capture storage is preserved.",false);
    }
    auto result = guardian.remove();
    if (!result.succeeded()) return result;
    return removeDirectory();
}
Result MacNetworkHelperState::removeDirectory()
{
    const auto name = connection.toString(QUuid::WithoutBraces).toLatin1();
    struct stat owned{}, named{};
    if (::fstat(directory,&owned) != 0) return failed("Cannot authenticate receipt cleanup.",false);
    if (::fstatat(userDirectory,name.constData(),&named,AT_SYMLINK_NOFOLLOW) == 0) {
        if (owned.st_dev != named.st_dev || owned.st_ino != named.st_ino || ::unlinkat(userDirectory,name.constData(),AT_REMOVEDIR) != 0)
            return failed("Changed or nonempty receipt storage is preserved.",false);
    } else if (errno != ENOENT || owned.st_nlink != 0) return failed("Cannot confirm receipt directory removal.",false);
    if (::fsync(userDirectory) != 0) return failed("Network is restored; receipt removal synchronization remains.",false);
    guardian.close(); ::close(directory); directory = -1; return {};
}
