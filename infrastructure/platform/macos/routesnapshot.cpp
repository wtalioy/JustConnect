#include "tunroutes.h"
#include <QJsonObject>
#include <QUuid>
#include <arpa/inet.h>
#include <cstring>
#include <net/route.h>
#include <sys/sysctl.h>

QString macBootSession()
{
    char value[64]{}; size_t size = sizeof(value);
    if (::sysctlbyname("kern.bootsessionuuid", value, &size, nullptr, 0) != 0 || !size || size > sizeof(value)
        || !std::memchr(value, 0, size)) return {};
    const QUuid id(QString::fromLatin1(value));
    return id.isNull() ? QString{} : id.toString(QUuid::WithoutBraces);
}

QString macRoutePrefix(const QJsonObject &addresses, quint32 flags)
{
    const auto destination = QByteArray::fromHex(addresses[QString::number(RTAX_DST)].toString().toLatin1());
    const auto mask = QByteArray::fromHex(addresses[QString::number(RTAX_NETMASK)].toString().toLatin1());
    if (destination.size() < 8 || quint8(destination[1]) != AF_INET) return {};
    quint32 ip = 0, netmask = 0;
    std::memcpy(&ip, destination.constData()+4, sizeof(ip));
    ip = ntohl(ip);
    if (flags & RTF_HOST) netmask = 0xffffffffu;
    else {
        if (!(addresses.contains(QString::number(RTAX_NETMASK))) || mask.size() > int(sizeof(sockaddr_in))) return {};
        sockaddr_in native{};
        std::memcpy(&native, mask.constData(), size_t(mask.size()));
        netmask = ntohl(native.sin_addr.s_addr);
    }
    int bits = 0;
    while (bits < 32 && (netmask & (1u<<(31-bits)))) ++bits;
    const quint32 expected = bits ? 0xffffffffu<<(32-bits) : 0;
    if (netmask != expected || (ip & netmask) != ip) return {};
    const in_addr native{htonl(ip)};
    char text[INET_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET, &native, text, sizeof(text))) return {};
    return QString::fromLatin1(text)+"/"+QString::number(bits);
}

MacRouteSnapshot readMacRoutes()
{
    using Status = PlatformOperationResult::Status;
    const MacRouteSnapshot invalid{{Status::Failed, "Cannot read a complete bounded native macOS IPv4 route snapshot."}, {}};
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    QByteArray bytes(NetworkJournalMaxBytes, Qt::Uninitialized);
    size_t size = size_t(bytes.size());
    if (::sysctl(mib, 6, bytes.data(), &size, nullptr, 0) != 0 || size > size_t(bytes.size())) return invalid;
    bytes.resize(qsizetype(size));
    QJsonArray rows;
    qsizetype offset = 0;
    while (offset < bytes.size()) {
        if (bytes.size()-offset < qsizetype(sizeof(rt_msghdr))) return invalid;
        rt_msghdr header{};
        std::memcpy(&header, bytes.constData()+offset, sizeof(header));
        if (header.rtm_msglen < sizeof(header) || header.rtm_msglen > bytes.size()-offset
            || header.rtm_version != RTM_VERSION || header.rtm_type != RTM_GET
            || (quint32(header.rtm_addrs) & ~((1u<<RTAX_MAX)-1))) return invalid;
        QJsonObject addresses;
        qsizetype position = offset+sizeof(header), end = offset+header.rtm_msglen;
        for (int index = 0; index < RTAX_MAX; ++index) {
            if (!(header.rtm_addrs & (1<<index))) continue;
            if (end-position < 2) return invalid;
            const auto length = quint8(bytes[position]);
            // Darwin routing sockaddrs use 32-bit alignment on both architectures.
            const qsizetype aligned = length ? (qsizetype(length)+3)&~qsizetype(3) : 4;
            if (aligned > end-position || length > end-position) return invalid;
            const auto address = bytes.mid(position, length);
            addresses[QString::number(index)] = QString::fromLatin1(address.toHex());
            position += aligned;
        }
        if (position != end) return invalid;
        const auto prefix = macRoutePrefix(addresses, quint32(header.rtm_flags));
        if (prefix.isEmpty()) return invalid;
        const auto &m = header.rtm_rmx;
        QJsonArray metrics{qint64(m.rmx_locks), qint64(m.rmx_mtu), qint64(m.rmx_hopcount), qint64(m.rmx_expire),
            qint64(m.rmx_recvpipe), qint64(m.rmx_sendpipe), qint64(m.rmx_ssthresh), qint64(m.rmx_rtt), qint64(m.rmx_rttvar)};
        for (const auto value : m.rmx_filler) metrics.append(qint64(value));
        // Packet/use counters and the derived interface-reference bit do not configure routing.
        rows.append(QJsonObject{{"prefix", prefix}, {"index", header.rtm_index},
            {"flags", qint64(quint32(header.rtm_flags)&~quint32(RTF_IFREF))}, {"addresses", addresses}, {"metrics", metrics}});
        if (rows.size() > MacRouteSnapshotRows) return invalid;
        offset = end;
    }
    return {{}, rows};
}
