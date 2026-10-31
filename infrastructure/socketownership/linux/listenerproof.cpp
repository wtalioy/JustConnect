#include "listenerproof.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QFile>
#include <QSet>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <climits>
#include <algorithm>
#include <cstring>

namespace {
quint64 integer(const QJsonValue &value) {
    if (!value.isString()) return 0;
    bool okay = false;
    const auto result = value.toString().toULongLong(&okay);
    return okay && result && QString::number(result) == value.toString() ? result : 0;
}
struct Endpoint {
    int family;
    std::array<unsigned char,16> address{};
    quint16 port;
};
std::optional<Endpoint> endpoint(const QString &value) {
    const auto portIndex = value.lastIndexOf(':');
    if (portIndex < 0) return {};
    auto host = value.left(portIndex);
    if (host.startsWith('[') && host.endsWith(']')) host = host.mid(1, host.size()-2);
    Endpoint result{host.contains(':') ? AF_INET6 : AF_INET};
    if (::inet_pton(result.family,host.toLatin1().constData(),result.address.data()) != 1) return {};
    const bool loopback = result.family == AF_INET ? result.address[0] == 127
        : std::all_of(result.address.cbegin(),result.address.cend()-1,[](unsigned char value) { return !value; }) && result.address.back() == 1;
    bool okay = false;
    const auto port = value.mid(portIndex+1).toUInt(&okay);
    char text[INET6_ADDRSTRLEN]{};
    if (!loopback || !okay || !port || port > 65535 || !::inet_ntop(result.family,result.address.data(),text,sizeof(text))) return {};
    const auto address = QString::fromLatin1(text);
    const auto canonical = result.family == AF_INET6 ? "[" + address + "]:" + QString::number(port) : address + ':' + QString::number(port);
    if (canonical != value) return {};
    result.port = quint16(port);
    return result;
}
quint64 started(const QByteArray &base) {
    QFile file(base + "/stat");
    if (!file.open(QIODevice::ReadOnly)) return 0;
    const auto bytes = file.read(65537);
    if (bytes.size() > 65536) return 0;
    const auto close = bytes.lastIndexOf(')');
    const auto fields = bytes.mid(close+1).simplified().split(' ');
    if (close < 0 || fields.size() < 20 || fields[0] == "Z" || fields[0] == "X") return 0;
    bool okay = false;
    const auto value = fields[19].toULongLong(&okay);
    return okay ? value : 0;
}
std::optional<QSet<QByteArray>> sockets(const QByteArray &base) {
    DIR *directory = ::opendir((base + "/fd").constData());
    if (!directory) return {};
    const auto close = qScopeGuard([&] { ::closedir(directory); });
    QSet<QByteArray> result;
    int count = 0;
    errno = 0;
    while (auto *entry = ::readdir(directory)) {
        if (++count > 8192) return {};
        std::array<char,128> bytes{};
        const auto length = ::readlinkat(::dirfd(directory),entry->d_name,bytes.data(),bytes.size());
        if (length > 0 && length < qsizetype(bytes.size())) {
            const QByteArray value(bytes.data(),length);
            if (value.startsWith("socket:[") && value.endsWith(']')) result.insert(value.mid(8,value.size()-9));
        }
        // Descriptors may close while this read-only snapshot is being taken.
        errno = 0;
    }
    if (errno) return {};
    return result;
}
std::optional<Endpoint> address(QByteArray value) {
    if (value.size() != 8 && value.size() != 32) return {};
    const auto bytes = QByteArray::fromHex(value);
    if (bytes.size()*2 != value.size()) return {};
    Endpoint result{bytes.size() == 4 ? AF_INET : AF_INET6};
    for (int offset=0;offset<bytes.size();offset+=4)
        for (int j=0;j<4;++j) result.address[offset+j] = quint8(bytes[offset+3-j]);
    if (result.family == AF_INET6 && result.address[10] == 0xff && result.address[11] == 0xff
        && std::all_of(result.address.cbegin(),result.address.cbegin()+10,[](unsigned char value) { return !value; })) {
        std::copy(result.address.cbegin()+12,result.address.cend(),result.address.begin());
        std::fill(result.address.begin()+4,result.address.end(),0);
        result.family = AF_INET;
    }
    return result;
}
}
bool validLinuxListenerRequest(const QJsonObject &request) {
    if (request.size() != 3 || !integer(request["pid"]) || integer(request["pid"]) > INT_MAX
        || !integer(request["started"]) || !request["endpoints"].isArray()) return false;
    const auto endpoints = request["endpoints"].toArray();
    if (endpoints.isEmpty() || endpoints.size() > LinuxProxyListenerLimit) return false;
    QSet<QString> seen;
    for (const auto &value : endpoints) {
        if (!value.isString() || !endpoint(value.toString()) || seen.contains(value.toString())) return false;
        seen.insert(value.toString());
    }
    return true;
}
bool validLinuxListenerProofs(const QJsonObject &request, const QJsonArray &proofs) {
    if (!validLinuxListenerRequest(request) || proofs.size() > LinuxProxyListenerLimit) return false;
    QSet<QString> seen;
    for (const auto &value : proofs) {
        if (!value.isObject()) return false;
        const auto proof = value.toObject();
        const auto endpoint = proof["endpoint"].toString();
        if (proof.size() != 4 || proof["pid"] != request["pid"] || proof["started"] != request["started"]
            || !request["endpoints"].toArray().contains(endpoint) || !integer(proof["inode"]) || seen.contains(endpoint)) return false;
        seen.insert(endpoint);
    }
    return true;
}
std::optional<QJsonArray> readLinuxListenerProofs(const QJsonObject &request) {
    if (!validLinuxListenerRequest(request)) return {};
    const auto base = "/proc/" + QByteArray::number(integer(request["pid"]));
    const auto matches = [&] { return started(base) == integer(request["started"]) && sameLinuxNetworkNamespace(base + "/ns/net"); };
    if (!matches()) return QJsonArray{};
    const auto owned = sockets(base);
    if (!owned) return {};
    QJsonArray result;
    QSet<QString> proved;
    for (const auto *table : {"tcp","tcp6"}) {
        QFile file(QStringLiteral("/proc/net/") + table);
        if (!file.open(QIODevice::ReadOnly)) return {};
        const auto bytes = file.read(4*1024*1024+1);
        if (bytes.size() > 4*1024*1024) return {};
        for (const auto &line : bytes.split('\n')) {
            const auto fields = line.simplified().split(' ');
            if (fields.size() < 10 || fields[3] != "0A" || !owned->contains(fields[9])) continue;
            const auto parts = fields[1].split(':');
            if (parts.size() != 2) continue;
            const auto host = address(parts[0]);
            bool okay = false;
            const auto port = parts[1].toUInt(&okay,16);
            if (!host || !okay || !port || port > 65535) continue;
            const auto inode = QString::fromLatin1(fields[9]);
            if (!integer(inode)) continue;
            for (const auto &value : request["endpoints"].toArray()) {
                const auto target = endpoint(value.toString());
                if (!proved.contains(value.toString()) && host->family == target->family
                    && (std::all_of(host->address.cbegin(),host->address.cend(),[](unsigned char value) { return !value; }) || host->address == target->address) && port == target->port) {
                    result.append(QJsonObject{{"pid",request["pid"]},{"started",request["started"]},{"endpoint",value},{"inode",inode}});
                    proved.insert(value.toString());
                }
            }
        }
    }
    return matches() ? std::optional<QJsonArray>(result) : std::optional<QJsonArray>(QJsonArray{});
}
