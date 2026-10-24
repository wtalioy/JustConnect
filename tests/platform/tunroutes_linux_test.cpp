#include "infrastructure/platform/linux/tunroutes.h"
#include "infrastructure/platform/linux/iprouteutility.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QFile>
#include <QJsonDocument>
#include <QScopeGuard>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <linux/capability.h>
#include <poll.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }

static void ip(const QStringList &args)
{
    const auto result = runPlatformCommand(trustedIpRouteUtility(), args);
    check(result.result.succeeded(), qPrintable(result.result.detail));
}

static QJsonArray rows()
{
    const auto result = runPlatformCommand(trustedIpRouteUtility(), {"-j", "-4", "route", "show", "table", "main"});
    const auto document = QJsonDocument::fromJson(result.output.toUtf8());
    check(result.result.succeeded() && document.isArray(), "Read the independent kernel route inventory");
    return document.array();
}

static QStringList inventory()
{
    QStringList result;
    for (const auto &row : rows()) result.append(QString::fromUtf8(QJsonDocument(row.toObject()).toJson(QJsonDocument::Compact)));
    result.sort();
    return result;
}

static bool hasRoute(const QString &prefix, const QString &device)
{
    for (const auto &value : rows()) {
        const auto row = value.toObject();
        const auto destination = row["dst"].toString();
        if ((destination == prefix || destination + "/32" == prefix) && row["dev"] == device) return true;
    }
    return false;
}

static void packets(const UnixTunDevice &device, const QString &source, const QString &target = "198.18.4.7")
{
    const int udp = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    check(udp >= 0, "Open the ordinary UDP route witness");
    const auto close = qScopeGuard([&] { ::close(udp); });
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(54321);
    check(::inet_pton(AF_INET, target.toLatin1().constData(), &destination.sin_addr) == 1, "Parse the owned host-route fixture");
    const QByteArray payload("owned-route");
    check(::sendto(udp, payload.constData(), size_t(payload.size()), 0, reinterpret_cast<sockaddr *>(&destination), sizeof(destination)) == payload.size(),
          "The kernel could not submit ordinary UDP through the owned route");
    const int flags = ::fcntl(device.descriptor(), F_GETFL);
    check(flags >= 0 && ::fcntl(device.descriptor(), F_SETFL, flags | O_NONBLOCK) == 0, "Bound native packet reads");
    QByteArray packet(65536, Qt::Uninitialized);
    QDeadlineTimer deadline(3000);
    int header = 0;
    while (true) {
        pollfd event{device.descriptor(), POLLIN, 0};
        check(!deadline.hasExpired() && ::poll(&event, 1, int(deadline.remainingTime())) == 1, "Ordinary UDP did not enter the actual owned TUN route");
        const auto size = ::read(device.descriptor(), packet.data(), size_t(packet.size()));
        if (size < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (size < 28 || (quint8(packet[0]) >> 4) != 4 || quint8(packet[9]) != IPPROTO_UDP) continue;
        header = (quint8(packet[0]) & 15) * 4;
        if (header < 20 || size != header + 8 + payload.size() || std::memcmp(packet.constData() + header + 8, payload.constData(), size_t(payload.size())) != 0) continue;
        packet.resize(size);
        break;
    }
    in_addr local{};
    check(::inet_pton(AF_INET, source.toLatin1().constData(), &local) == 1
          && std::memcmp(packet.constData() + 12, &local, 4) == 0
          && std::memcmp(packet.constData() + 16, &destination.sin_addr, 4) == 0,
          "The owned route selected the wrong source or destination");
    for (int i = 0; i < 4; ++i) std::swap(packet.data()[12 + i], packet.data()[16 + i]);
    for (int i = 0; i < 2; ++i) std::swap(packet.data()[header + i], packet.data()[header + 2 + i]);
    packet[10] = packet[11] = packet[header + 6] = packet[header + 7] = 0;
    quint32 checksum = 0;
    for (int i = 0; i < header; i += 2) checksum += (quint32(quint8(packet[i])) << 8) | quint8(packet[i + 1]);
    while (checksum >> 16) checksum = (checksum & 0xffffu) + (checksum >> 16);
    packet[10] = char((~checksum >> 8) & 255);
    packet[11] = char(~checksum & 255);
    check(::write(device.descriptor(), packet.constData(), size_t(packet.size())) == packet.size(), "Inject the actual owned-route return packet");
    pollfd returned{udp, POLLIN, 0};
    check(::poll(&returned, 1, 3000) == 1, "Strict reverse-path filtering rejected the owned-route return packet");
    QByteArray reply(64, Qt::Uninitialized);
    sockaddr_in peer{};
    socklen_t peerSize = sizeof(peer);
    const auto count = ::recvfrom(udp, reply.data(), size_t(reply.size()), MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&peer), &peerSize);
    check(count == payload.size() && reply.first(count) == payload && peer.sin_addr.s_addr == destination.sin_addr.s_addr
          && peer.sin_port == destination.sin_port, "The actual UDP route witness received the wrong return payload or endpoint");
}

#include "tunroutes_recovery_test.h"

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    using Status = PlatformOperationResult::Status;
    if(const auto command=captureRecoveryCommand(app.arguments()))return *command;
    const auto &source=captureSource,&peer=capturePeer;
    UnixTunDevice device;
    int reads = 0;
    LinuxTunRoutes inactive([&](const QString &, const QStringList &) {
        ++reads;
        return PlatformCommandResult{{Status::Failed, "Unexpected read"}, {}};
    });
    check(!inactive.apply(device, source, peer, {"198.18.0.0/24"}).succeeded() && reads == 0 && inactive.snapshot().isEmpty(),
          "Routes reached the operating system without a live owned device");
    int checkpoints=0;
    check(!inactive.recover(QUuid::createUuid(),{},[&](const QJsonObject &){++checkpoints;return PlatformOperationResult{};}).succeeded()
          && reads==0 && checkpoints==0 && inactive.snapshot().isEmpty(),"Invalid saved capture authority reached a command or storage operation");
    if (argc == 1) {
        check(::geteuid() != 0, "Run the ordinary route check without root");
        std::cout << "PASS: missing device ownership cannot reach route operations\n";
        return 0;
    }
    struct stat current{}, initial{};
    check(argc == 2 && app.arguments()[1] == "--isolated" && ::geteuid() == 0
          && ::stat("/proc/self/ns/net", &current) == 0 && ::stat("/proc/1/ns/net", &initial) == 0
          && (current.st_dev != initial.st_dev || current.st_ino != initial.st_ino), "Refusing the host network namespace");
    for (const auto &name : {"all", "default"}) {
        QFile filter(QString("/proc/sys/net/ipv4/conf/%1/rp_filter").arg(name));
        check(filter.open(QIODevice::WriteOnly) && filter.write("1") == 1, "Keep strict reverse-path filtering in the private namespace");
    }
    check(device.createIpv4(QUuid::createUuid(), source, peer, 1400).succeeded(), "Create and configure the exclusively owned route fixture device");
    ip({"link", "add", "foreign0", "type", "dummy"});
    ip({"link", "set", "foreign0", "up"});
    ip({"address", "add", "192.0.2.1/24", "dev", "foreign0"});
    ip({"route", "add", "198.18.1.0/24", "dev", "foreign0", "proto", "static", "metric", "7"});
    ip({"route", "add", "198.18.1.7/32", "dev", "foreign0", "proto", "4", "metric", "7"});
    ip({"route", "add", "default", "via", "192.0.2.2", "dev", "foreign0", "proto", "4"});
    ip({"route", "add", "128.0.0.0/1", "via", "192.0.2.2", "dev", "foreign0", "proto", "4"});
    const auto baseline = inventory();
    const QString embedded = QString("198.18.0.0") + QChar(0) + "\nlink set lo down/24";
    for (const auto &bad : {QString("default"), QString("0.0.0.0/0"), QString("0.0.0.0/1"), QString("198.18.2.1/24"),
                           QString("198.018.2.0/24"), QString("198.18.2.0/024"), QString("::/64"), embedded})
        check(!inactive.apply(device, source, peer, {bad}).succeeded() && reads == 0 && inactive.snapshot().isEmpty(),
              "Invalid capture prefix reached a command or ownership record");
    for (const auto &pair : {std::pair{QString("0.0.0.0"), peer}, std::pair{QString("192.0.2.1"), peer},
                            std::pair{source, source}, std::pair{source, QString("198.19.0.3")}})
        check(!inactive.apply(device, pair.first, pair.second, {"198.18.2.0/24"}).succeeded()
              && reads == 0 && inactive.snapshot().isEmpty(), "Unassigned or zero point-to-point addresses reached route operations");
    LinuxTunRoutes routes;
    for (const auto &prefix : QStringList{"198.18.1.0/24", "198.18.1.7/32", peer + "/32"})
        check(!routes.apply(device, source, peer, {prefix}).succeeded() && routes.snapshot().isEmpty() && inventory() == baseline,
              "An existing external subnet or host route was adopted or changed");
    QStringList capacity;
    for (int i = 0; i < LinuxRouteSnapshotRows; ++i) capacity.append(QString("198.19.%1.%2/32").arg(16 + i / 256).arg(i % 256));
    const auto excessive = routes.apply(device, source, peer, capacity);
    check(!excessive.succeeded() && !excessive.mayHaveChanged && routes.snapshot().isEmpty() && inventory() == baseline,
          "A batch exceeding the complete post-apply snapshot capacity wrote unrecoverable routes");
    const auto &prefixes=capturePrefixes;
    check(routes.apply(device, source, peer, prefixes + QStringList{prefixes.first()}).succeeded(), "Apply and confirm owned capture routes");
    check(routes.snapshot()["routes"].toArray().size() == prefixes.size() && hasRoute(prefixes[0], device.name())
          && hasRoute(prefixes[1], device.name()) && hasRoute(prefixes[2], device.name()),
          "Applied records differ from the actual kernel routes or duplicate an entry");
    const auto selected = runPlatformCommand(trustedIpRouteUtility(), {"-j", "-4", "route", "get", "198.18.4.7"});
    check(selected.result.succeeded() && QJsonDocument::fromJson(selected.output.toUtf8()).array().first().toObject()["dev"] == device.name(),
          "The native kernel did not select the owned capture route");
    packets(device, source);
    const auto original = routes.snapshot();
    check(routes.extend(device,{"198.18.2.9","198.18.6.7","198.18.6.7"}).succeeded()
          && routes.snapshot()["routes"].toArray().size() == original["routes"].toArray().size()+1,
          "DNS extension duplicated covered routes or failed to append a host");
    packets(device,source,"198.18.6.7");
    const auto extended = routes.snapshot();
    const auto extendedInventory = inventory();
    check(routes.extend(device,{"198.18.6.7"}).succeeded() && routes.snapshot() == extended && inventory() == extendedInventory,
          "Repeated DNS publication changed its route identity");
    for (const auto &invalid : {QString("127.0.0.1"),source,peer,QString("198.18.7.0/24")})
        check(!routes.extend(device,{invalid}).succeeded() && routes.snapshot() == extended && inventory() == extendedInventory,
              "Invalid DNS capture address changed active ownership");
    check(!routes.extend(device,{"198.18.7.7"},[&](const QJsonObject &record) {
        check(inventory() == extendedInventory,"DNS capture wrote before its checkpoint");
        return record == extended ? PlatformOperationResult{} : PlatformOperationResult{Status::Failed,"Refused DNS checkpoint"};
    }).succeeded() && routes.snapshot() == extended && inventory() == extendedInventory,
          "Failed DNS checkpoint damaged existing capture routes");
    const auto active = inventory();
    UnixTunDevice other;
    check(other.create(QUuid::createUuid()).succeeded(), "Create another connection's device");
    check(!routes.restore(other).succeeded() && inventory() == active && !routes.snapshot().isEmpty(),
          "A different owner restored or discarded the original route records");
    check(routes.restore(device).succeeded() && routes.snapshot().isEmpty() && inventory() == baseline,
          "Normal recovery changed the original route inventory");
    check(routes.restore(device).succeeded() && inventory() == baseline, "Repeated recovery changed an external route");
    {
        LinuxTunRoutes changing;
        check(changing.apply(device,source,peer,prefixes).succeeded(),"Prepare live capture reconciliation");
        const QStringList next{prefixes[2],"198.18.6.7/32"};
        QJsonObject durable;
        const auto checkpoint = [&](const QJsonObject &value) { durable = value; return PlatformOperationResult{}; };
        check(changing.reconcile(device,next,checkpoint).succeeded()
              && !hasRoute(prefixes[0],device.name()) && !hasRoute(prefixes[1],device.name())
              && hasRoute(next[0],device.name()) && hasRoute(next[1],device.name())
              && durable == changing.snapshot(),"Live reconciliation did not persist exact capture ownership");
        packets(device,source,"198.18.6.7");
        const auto held = inventory();
        check(!changing.reconcile(device,{next[0],"default"},checkpoint).succeeded() && inventory() == held,
              "Invalid replacement changed existing routes");
        check(!changing.reconcile(device,{next[0]},[&](const QJsonObject &value) {
            for (const auto &route : value["routes"].toArray())
                if (route.toObject()["delete_started"] == true) return PlatformOperationResult{PlatformOperationResult::Status::Failed,"refused withdrawal intent"};
            return PlatformOperationResult{};
        }).succeeded() && inventory() == held,"Withdrawal preceded its durable checkpoint");
        check(changing.reconcile(device,next,checkpoint).succeeded() && inventory() == held,
              "Retry lost a retained capture after a rejected deletion checkpoint");
        check(changing.reconcile(device,{},checkpoint).succeeded() && changing.snapshot()["routes"].toArray().isEmpty()
              && inventory() == baseline && device.descriptor() >= 0,"Empty live capture set destroyed its active device or retained routes");
        check(changing.reconcile(device,next,checkpoint).succeeded(),"An empty active capture set could not expand again");
        LinuxTunRoutes recovered;
        check(recovered.recover(device.owner(),durable).succeeded() && inventory() == baseline,
              "Fresh recovery lost ownership after live replacement");
        check(changing.restore(device).succeeded(),"Release independently recovered live capture metadata");
    }
    {
        LinuxTunRoutes changing;
        check(changing.apply(device,source,peer,prefixes).succeeded(),"Prepare retained-route external-change fixture");
        const auto metric = QString::number(changing.snapshot()["metric"].toInteger());
        bool changed = false;
        const auto replaced = changing.reconcile(device,{prefixes[2]},[&](const QJsonObject &record) {
            for (const auto &row : record["routes"].toArray()) if (!changed && row.toObject()["delete_started"] == true) {
                ip({"route","replace",prefixes[2],"dev","foreign0","proto","4","scope","0","metric",metric,
                    "src","192.0.2.1","via","192.0.2.2"});
                changed = true;
            }
            return PlatformOperationResult{};
        });
        check(changed && !replaced.succeeded() && hasRoute(prefixes[0],device.name()) && hasRoute(prefixes[2],"foreign0"),
              "Reconciliation ignored an external retained-route change or deleted before revalidation");
        check(changing.restore(device).succeeded() && hasRoute(prefixes[2],"foreign0"),"Recovery deleted the externally replaced retained route");
        ip({"route","del",prefixes[2],"metric",metric});
        check(inventory() == baseline,"Retained-route fixture changed the original inventory");
    }
    for (const bool changedSource : {false, true}) {
        check(routes.apply(device, source, peer, prefixes).succeeded(), "Apply external-change fixture routes");
        const auto metric = QString::number(routes.snapshot()["metric"].toInteger());
        QStringList change{"route", "replace", prefixes[0], "dev", changedSource ? device.name() : QString("foreign0"),
                           "proto", "4", "scope", "0", "metric", metric};
        change << "src" << "192.0.2.1" << "via" << (changedSource ? peer : QString("192.0.2.2"));
        ip(change);
        const auto recovered = routes.restore(device);
        check(recovered.succeeded() && !recovered.detail.isEmpty() && routes.snapshot().isEmpty()
              && hasRoute(prefixes[0], changedSource ? device.name() : QString("foreign0")) && !hasRoute(prefixes[1], device.name()),
              "Recovery deleted external device/source changes or retained unchanged owned routes");
        // Only this fixture removes the externally rewritten route retained by the backend.
        ip({"route", "del", prefixes[0], "metric", metric});
        check(inventory() == baseline, "External-change fixture lost an unrelated route");
    }
    for (const bool changedGateway : {false, true}) {
        int reads = 0;
        LinuxTunRoutes *recovering = nullptr;
        QString racedMetric;
        LinuxTunRoutes race([&](const QString &program, const QStringList &args) {
            const auto snapshot = runPlatformCommand(program, args);
            if (++reads == 3) {
                racedMetric = QString::number(recovering->snapshot()["metric"].toInteger());
                QStringList changed{"route", "replace", prefixes[0], "dev", device.name(), "proto", "4", "scope", "0",
                    "metric", racedMetric, "src", changedGateway ? source : QString("192.0.2.1"),
                    "via", changedGateway ? QString("198.19.0.3") : peer};
                if (changedGateway) changed << "onlink";
                ip(changed);
            }
            return snapshot;
        });
        recovering = &race;
        check(race.apply(device, source, peer, prefixes).succeeded(), "Prepare the post-read external-write fixture");
        const auto recovered = race.restore(device);
        check(recovered.succeeded() && !recovered.detail.isEmpty() && race.snapshot().isEmpty()
              && hasRoute(prefixes[0], device.name()) && !hasRoute(prefixes[1], device.name()) && !hasRoute(prefixes[2], device.name()),
              "Deletion lost its nonzero source/gateway guard or stopped recovering unrelated owned routes");
        ip({"route", "del", prefixes[0], "metric", racedMetric});
        check(inventory() == baseline, "Post-read external-write fixture changed the original inventory");
    }
    bool inserted = false;
    QString collisionMetric;
    LinuxTunRoutes *pending = nullptr;
    LinuxTunRoutes partial([&](const QString &program, const QStringList &args) {
        const auto snapshot = runPlatformCommand(program, args);
        if (!inserted) {
            inserted = true;
            collisionMetric = QString::number(pending->snapshot()["metric"].toInteger());
            ip({"route", "add", prefixes[1], "dev", "foreign0", "proto", "static", "scope", "link", "metric", collisionMetric});
        }
        return snapshot;
    });
    pending = &partial;
    const auto failed = partial.apply(device, source, peer, prefixes);
    check(!failed.succeeded() && failed.mayHaveChanged && partial.snapshot().isEmpty()
          && !hasRoute(prefixes[0], device.name()) && hasRoute(prefixes[1], "foreign0"),
          "Partial batch failure leaked an owned route or deleted the concurrent external route");
    ip({"route", "del", prefixes[1], "metric", collisionMetric});
    check(inventory() == baseline, "Partial batch rollback changed unrelated routes");
    for (const int failedRead : {2, 3}) {
        int calls = 0;
        LinuxTunRoutes fault([&](const QString &program, const QStringList &args) {
            if (++calls == failedRead) return PlatformCommandResult{{Status::TimedOut, "Injected route readback failure"}, {}};
            return runPlatformCommand(program, args);
        });
        const auto applied = fault.apply(device, source, peer, prefixes);
        if (failedRead == 2) {
            check(applied.status == Status::TimedOut && fault.snapshot().isEmpty() && inventory() == baseline,
                  "Failed application readback did not roll back actual kernel routes");
        } else {
            check(applied.succeeded(), "Prepare retryable recovery fixture");
            const auto owned = inventory();
            check(!fault.restore(device).succeeded() && !fault.snapshot().isEmpty() && inventory() == owned,
                  "Failed recovery discarded ownership records or changed routes without readback");
            check(fault.restore(device).succeeded() && fault.snapshot().isEmpty() && inventory() == baseline,
                  "Retry could not recover the retained owned routes");
        }
    }
    int unknownReads = 0;
    LinuxTunRoutes *unconfirmed = nullptr;
    QString unknownMetric;
    LinuxTunRoutes unknown([&](const QString &program, const QStringList &args) {
        if (++unknownReads == 2) {
            unknownMetric = QString::number(unconfirmed->snapshot()["metric"].toInteger());
            ip({"route", "replace", prefixes[0], "dev", device.name(), "proto", "4", "scope", "0", "metric", unknownMetric, "src", "192.0.2.1", "via", peer});
        }
        return runPlatformCommand(program, args);
    });
    unconfirmed = &unknown;
    check(!unknown.apply(device, source, peer, prefixes).succeeded() && !unknown.snapshot().isEmpty()
          && hasRoute(prefixes[0], device.name()) && !hasRoute(prefixes[1], device.name()),
          "Unconfirmed externally changed values were deleted or their recovery obligation was discarded");
    ip({"route", "replace", prefixes[0], "dev", device.name(), "proto", "4", "scope", "0", "metric", unknownMetric, "src", source, "via", peer});
    check(unknown.restore(device).succeeded() && unknown.snapshot().isEmpty() && inventory() == baseline,
          "Unconfirmed route records could not recover after their expected shape returned");
    int renameReads = 0;
    QStringList renamedInventory;
    LinuxTunRoutes renamed([&](const QString &program, const QStringList &args) {
        const auto snapshot = runPlatformCommand(program, args);
        if (++renameReads == 3) {
            ip({"link", "set", device.name(), "down"});
            ip({"link", "set", device.name(), "name", "renamed0"});
            renamedInventory = inventory();
        }
        return snapshot;
    });
    check(renamed.apply(device, source, peer, prefixes).succeeded(), "Apply the identity-change fixture");
    check(!renamed.restore(device).succeeded() && !renamed.snapshot().isEmpty() && inventory() == renamedInventory,
          "Recovery acted on an interface renamed during its native read");
    ip({"link", "set", "renamed0", "name", device.name()});
    ip({"link", "set", device.name(), "up"});
    check(renamed.restore(device).succeeded() && inventory() == baseline, "Original identity could not recover its retained records");
    captureRecoveryTests(device,baseline);
    {
        LinuxTunRoutes growing;
        check(growing.apply(device,source,peer,{"198.18.8.1/32"}).succeeded()
              && growing.extend(device,{"198.18.8.2"}).succeeded(),"Prepare persisted capture extension");
        LinuxTunRoutes recovered;
        check(recovered.recover(device.owner(),growing.snapshot()).succeeded() && inventory() == baseline,
              "A fresh capture backend could not restore appended DNS routes");
        check(growing.restore(device).succeeded(),"Release already restored capture metadata");
    }
    check(::setgroups(0, nullptr) == 0 && ::setgid(65534) == 0 && ::setuid(65534) == 0, "Drop all test route privileges");
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct caps[2]{};
    check(::getuid() == ::geteuid() && ::geteuid() != 0 && ::getgroups(0, nullptr) == 0
          && ::syscall(SYS_capget, &header, caps) == 0 && (caps[0].effective | caps[1].effective) == 0,
          "Route permission test retained root or capabilities");
    const auto denied = routes.apply(device, source, peer, prefixes);
    check(denied.status == Status::PermissionDenied && routes.snapshot().isEmpty() && inventory() == baseline,
          "Unprivileged route failure changed the kernel inventory or hid permission denial");
    std::cout << "PASS: owned route apply/readback, partial rollback, external changes, owner/rename rejection, recovery retry and zero-capability denial\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
