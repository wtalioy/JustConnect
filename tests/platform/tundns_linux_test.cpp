#include "infrastructure/dns/linux/tundns.h"
#include "infrastructure/dns/linux/linkdns.h"
#include "infrastructure/dns/linux/resolvedbus.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include "infrastructure/networkhelper/linux/networkhelper.h"
#include "infrastructure/networkjournal/networkjournal.h"
#include "infrastructure/process/command.h"
#include <QCoreApplication>
#include <QDBusConnection>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <csignal>
#include <fcntl.h>
#include <linux/capability.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using Result = PlatformOperationResult;
using Status = Result::Status;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static void success(const Result &result) { check(result.succeeded(), qPrintable(result.detail)); }
static QDBusConnection privateBus()
{
    check(::geteuid() == 0, "Native DNS tests require root inside private namespaces");
    QFile status("/proc/self/status");
    check(status.open(QIODevice::ReadOnly), "Read actual DNS worker capabilities");
    const auto rows = status.readAll().split('\n');
    bool limited = false;
    for (const auto &row : rows) if (row.startsWith("CapEff:")) {
        bool valid = false;
        limited = row.mid(7).trimmed().toULongLong(&valid, 16) == (1ULL << CAP_NET_ADMIN) && valid;
    }
    check(limited, "DNS worker must run with only CAP_NET_ADMIN, as the recovery service does");
    const auto hostNamespaces = qgetenv("JC_TEST_HOST_NAMESPACE_FDS").split(',');
    check(hostNamespaces.size() == 2, "Require host namespace handles opened by the isolated root harness");
    int position = 0;
    for (const auto *kind : {"net", "mnt"}) {
        struct stat here{}, host{};
        const auto suffix = QByteArray("/ns/") + kind;
        bool valid = false;
        const auto descriptor = hostNamespaces[position++].toInt(&valid);
        check(::stat(("/proc/thread-self" + suffix).constData(), &here) == 0
            && valid && descriptor >= 3 && ::fstat(descriptor, &host) == 0
            && (here.st_dev != host.st_dev || here.st_ino != host.st_ino), "Refusing host network or mounts");
    }
    struct stat socket{};
    check(::stat("/run/dbus/system_bus_socket", &socket) == 0 && S_ISSOCK(socket.st_mode) && socket.st_uid == 0,
          "A private root-owned resolver bus is required");
    const auto hostSocket = qgetenv("JC_TEST_HOST_BUS_ID").split(',');
    check(hostSocket.size() == 2 && (QByteArray::number(socket.st_dev) != hostSocket[0]
        || QByteArray::number(socket.st_ino) != hostSocket[1]), "Refusing the host system bus");
    auto bus = QDBusConnection::connectToBus("unix:path=/run/dbus/system_bus_socket", "owned-dns-test");
    check(bus.isConnected(), "Connect the isolated system resolver bus");
    return bus;
}
static QString resolver(const QStringList &args)
{
    QProcessEnvironment environment;
    const auto result = runPlatformCommand("/usr/bin/resolvectl", args, 3000, {}, environment);
    success(result.result); return result.output;
}
static QStringList settings(const QString &name)
{
    QStringList result;
    for (const auto *key : {"dns", "domain", "default-route"}) result.append(resolver({key, name}));
    return result;
}
static LinuxTunDns::CheckpointWriter writer(UnixNetworkJournal &journal)
{
    return [&journal](const QJsonObject &value) { return value.isEmpty() ? journal.remove() : journal.store(value); };
}
static void openJournal(UnixNetworkJournal &journal, const QString &path, const QUuid &owner)
{
    const int directory = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    check(directory >= 0, "Open private DNS journal");
    const auto result = journal.open(directory, owner); ::close(directory); success(result);
}
static void create(UnixTunDevice &device, const QUuid &owner)
{
    success(device.createIpv4(owner, "198.18.0.1", "198.18.0.2", 1400));
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    if (argc == 1) {
        check(::geteuid() != 0, "Ordinary DNS check must run without root");
        LinuxTunDns dns(QDBusConnection::systemBus()); UnixTunDevice device;
        check(dns.apply(device, {"campus.test"}).status == Status::PermissionDenied && dns.snapshot().isEmpty(),
              "Ordinary caller entered DNS mutation or retained responsibility");
        check(!dns.recover(QUuid::createUuid(), {}).succeeded(), "Unowned DNS recovery accepted");
        LinuxLinkDns original(QDBusConnection::systemBus());
        check(original.apply(QUuid::createUuid(), "lo", "127.0.0.1", 53535, {}).status == Status::PermissionDenied
            && original.snapshot().isEmpty() && !original.recover(QUuid::createUuid(), {}, {}).succeeded(),
            "Ordinary caller entered original-link DNS replacement or recovery");
        std::cout << "PASS: ordinary DNS mutation and unowned recovery rejected\n";
        return 0;
    }
    const auto bus = privateBus();
    if (argc == 4 && app.arguments()[1] == "--recover-link-dns-isolated") {
        const QUuid owner(app.arguments()[3]); UnixNetworkJournal journal;
        openJournal(journal, app.arguments()[2], owner);
        QJsonObject saved; success(journal.load(saved));
        LinuxLinkDns original(bus); success(original.recover(owner, saved, writer(journal)));
        check(original.snapshot().isEmpty(), "Recovered original DNS retained its journal");
        return 0;
    }
    if (argc == 5 && app.arguments()[1] == "--link-dns-isolated") {
        const auto interface = app.arguments()[2], source = app.arguments()[3];
        const auto index = ::if_nametoindex(interface.toLatin1().constData());
        bool validPort = false;
        const auto suppliedPort = app.arguments()[4].toUInt(&validPort);
        check(validPort && suppliedPort > 0 && suppliedPort <= 65535, "Require the actual prepared DNS listener port");
        const auto port = quint16(suppliedPort); const auto owner = QUuid::createUuid();
        const auto inspect = [&] {
            QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
            const auto state = LinuxResolved::readLink(bus, int(index), deadline); success(state.result); return state;
        };
        const auto before = inspect();
        const auto initial = settings(interface);
        QTemporaryDir directory; check(directory.isValid(), "Create original DNS journal directory");
        UnixNetworkJournal journal; openJournal(journal, directory.path(), owner);
        LinuxLinkDns original(bus);
        const auto missing = original.apply(owner, interface, source, port, {});
        check(!missing.succeeded() && !missing.mayHaveChanged && original.snapshot().isEmpty() && settings(interface) == initial,
              "Original DNS accepted mutation without a durable checkpoint");
        const auto rejected = original.apply(owner, interface, source, port, [](const QJsonObject &) {
            return Result{Status::Failed, "Injected original DNS checkpoint failure"};
        });
        check(!rejected.succeeded() && !rejected.mayHaveChanged && original.snapshot().isEmpty() && settings(interface) == initial,
              "Original DNS changed despite its failed write-ahead checkpoint");
        // Leave the durable pre-write state while the native property contains our unique endpoint.
        const auto interrupted = original.apply(owner, interface, source, port, [&](const QJsonObject &value) {
            if (value["phase"] == "active") return Result{Status::Failed, "Injected post-write checkpoint failure"};
            return writer(journal)(value);
        });
        check(!interrupted.succeeded() && interrupted.mayHaveChanged && original.snapshot()["phase"] == "active",
              "An interrupted original DNS write lost its recovery responsibility");
        const auto applied = settings(interface);
        LinuxLinkDns competing(bus);
        const auto competingResult = competing.apply(QUuid::createUuid(), interface, source, port, writer(journal));
        check(!competingResult.succeeded() && !competingResult.mayHaveChanged && competing.snapshot().isEmpty()
            && settings(interface) == applied, "A second connection nested ownership over an active DNS endpoint");
        check(applied[0] != initial[0] && applied[1] == initial[1] && applied[2] == initial[2],
              "Original DNS replacement changed domains or default routing");
        check(resolver({"query", "--type=A", "source-check.original.test"}).contains("203.0.113.9"),
              "The actual system resolver did not reach the assigned local DNS endpoint");
        LinuxLinkDns wrongOwner(bus);
        check(!wrongOwner.recover(QUuid::createUuid(), original.snapshot(), writer(journal)).succeeded() && wrongOwner.snapshot().isEmpty()
            && settings(interface) == applied, "A different owner recovered an original DNS setting");
        journal.close();
        success(runPlatformCommand(app.applicationFilePath(), {"--recover-link-dns-isolated", directory.path(), owner.toString(QUuid::WithoutBraces)}, 10000).result);
        const auto recovered = inspect();
        check(settings(interface) == initial && recovered.profile == before.profile && recovered.security == before.security,
              "New-process recovery failed to restore the exact native original DNS values");
        openJournal(journal, directory.path(), owner);
        success(original.restore(writer(journal)));
        success(original.apply(owner, interface, source, port, writer(journal)));
        const auto endpoint = original.snapshot()["after"].toArray().first().toObject();
        const auto owned = source + ":" + QString::number(port) + "#" + endpoint["name"].toString();
        resolver({"dns", interface, owned, "192.0.2.54"});
        const auto added = inspect();
        auto expectedExternal = added.profile["dns"].toArray();
        check(expectedExternal.size() == 2 && expectedExternal[0] == endpoint, "Prepare an actual external DNS addition");
        expectedExternal.removeFirst();
        bool cleanupFailed = false;
        const auto receipt = original.restore([&](const QJsonObject &value) {
            if (value.isEmpty() && !cleanupFailed) { cleanupFailed = true; return Result{Status::Failed, "Injected original DNS receipt failure"}; }
            return writer(journal)(value);
        });
        check(!receipt.succeeded() && receipt.mayHaveChanged && original.snapshot()["phase"] == "released",
              "Original DNS lost its completed-restoration receipt");
        const auto external = inspect();
        check(external.profile["dns"].toArray() == expectedExternal
            && external.profile["domains"] == before.profile["domains"] && external.profile["default_route"] == before.profile["default_route"],
            "Original DNS restoration overwrote an external server or another native property");
        resolver({"dns", interface, owned});
        const auto recreated = settings(interface);
        success(original.restore(writer(journal)));
        check(settings(interface) == recreated, "Receipt retry reclaimed an externally recreated identical DNS endpoint");
        QStringList restore{"dns", interface};
        for (const auto &value : before.profile["dns"].toArray()) {
            const auto row = value.toObject(); auto address = row["address"].toString();
            if (row["family"] == AF_INET6) address = '[' + address + ']';
            if (row["port"].toInteger() != 0) address += ':' + QString::number(row["port"].toInteger());
            if (!row["name"].toString().isEmpty()) address += '#' + row["name"].toString();
            restore.append(address);
        }
        resolver(restore);
        const auto setTLS = [&](const QString &mode) {
            QDeadlineTimer budget(10000);
            success(LinuxResolved::replyResult(LinuxResolved::call(bus, before.provider["owner"].toString(), LinuxResolved::managerPath,
                LinuxResolved::managerInterface, "SetLinkDNSOverTLS", {int(index), mode}, budget)));
        };
        setTLS("yes");
        const auto secure = original.apply(owner, interface, source, port, writer(journal));
        check(secure.status == Status::Unsupported && !secure.mayHaveChanged && original.snapshot().isEmpty()
            && settings(interface) == initial, "Encrypted native DNS was downgraded or changed before refusal");
        setTLS(before.security["DNSOverTLS"].toString());
        check(settings(interface) == initial, "Original DNS fixture did not restore its complete native state");
        std::cout << "PASS: existing-link DNS servers, unchanged domains/security, foreign additions and interrupted-write recovery\n";
        return 0;
    }
    if (argc == 3 && app.arguments()[1] == "--scan-isolated") {
        bool valid = false;
        const auto directory = app.arguments()[2].toInt(&valid);
        check(valid && directory >= 3, "Require the private helper recovery directory");
        const auto summary = recoverLinuxHelperRecords(directory);
        std::cout << QJsonDocument(summary.json()).toJson(QJsonDocument::Compact).constData() << '\n';
        return summary.succeeded() ? 0 : 1;
    }
    if (argc == 2 && app.arguments()[1] == "--absent-isolated") {
        UnixTunDevice device; create(device, QUuid::createUuid());
        LinuxTunDns dns(bus); const auto result = dns.apply(device, {"campus.test"});
        check(result.status == Status::Unsupported && !result.mayHaveChanged && dns.snapshot().isEmpty(),
              "Absent resolver was misclassified or modified the owned DNS state");
        std::cout << "PASS: absent resolver reports unsupported without starting a service or changing DNS\n"; return 0;
    }
    if (argc == 3 && app.arguments()[1] == "--foreign-provider-isolated") {
        bool valid = false;
        const auto control = app.arguments()[2].toInt(&valid);
        check(valid && control >= 3, "Invalid provider collision fixture channel");
        UnixTunDevice device; create(device, QUuid::createUuid());
        success(sendLinuxHelperPacket(control, {{"index", qint64(device.index())}}));
        QJsonObject ready; int received = -1;
        success(receiveLinuxHelperPacket(control, ready, received, 5000));
        if (received >= 0) ::close(received);
        check(received < 0 && ready == QJsonObject{{"ready", true}}, "Provider collision was not prepared");
        LinuxTunDns dns(bus);
        const auto result = dns.apply(device, {"campus.test"});
        check(result.status == Status::Unsupported && !result.mayHaveChanged && dns.snapshot().isEmpty(),
              "Resolver in another network namespace accepted the colliding TUN index");
        std::cout << "PASS: foreign resolver namespace rejected before checkpoint or DNS mutation despite colliding interface index\n";
        return 0;
    }
    if (argc == 4 && app.arguments()[1] == "--recover-isolated") {
        const QUuid owner(app.arguments()[3]); UnixNetworkJournal journal;
        openJournal(journal, app.arguments()[2], owner);
        QJsonObject saved; success(journal.load(saved));
        LinuxTunDns dns(bus);
        const auto result = dns.recover(owner, saved, writer(journal));
        if (!result.succeeded()) {
            check(!dns.snapshot().isEmpty(), "Uncertain DNS recovery lost its responsibility");
            std::cout << "RETAINED: " << qPrintable(result.detail) << '\n'; return 2;
        }
        check(dns.snapshot().isEmpty(), "Completed DNS recovery retained state");
        std::cout << "PASS: new process recovered the authenticated DNS journal\n"; return 0;
    }
    if (argc == 5 && app.arguments()[1] == "--prepare-isolated") {
        const int socket = app.arguments()[2].toInt(); const auto phase = app.arguments()[4];
        const auto owner = QUuid::createUuid(); UnixTunDevice device; create(device, owner);
        UnixNetworkJournal journal; openJournal(journal, app.arguments()[3], owner);
        success(sendLinuxHelperPacket(socket, {{"owner", owner.toString(QUuid::WithoutBraces)}, {"device", device.snapshot()}}, device.descriptor()));
        QString pendingKey;
        auto checkpoint = [&](const QJsonObject &record) {
            const auto result = writer(journal)(record); if (!result.succeeded()) return result;
            const auto pending = record["pending"].toObject(), applied = record["applied"].toObject();
            if (!pending.isEmpty()) for (const auto &key : pending.keys()) if (pending[key] != applied[key]) pendingKey = key;
            const auto marker = QString(record["restoring"].toBool() ? "restore-" : "apply-") + pendingKey
                + (pending.isEmpty() ? "-confirmed" : "-pending");
            if (!record.isEmpty() && record["released"] != true && marker == phase) {
                success(sendLinuxHelperPacket(socket, {{"checkpoint", marker}}));
                ::raise(SIGSTOP);
                throw std::runtime_error("Stopped checkpoint fixture unexpectedly resumed");
            }
            return result;
        };
        LinuxTunDns dns(bus); success(dns.apply(device, {"campus.test"}, checkpoint));
        if (phase == "flow") {
            success(sendLinuxHelperPacket(socket, {{"ready", true}}));
            QJsonObject answer; int extra = -1;
            const auto result = receiveLinuxHelperPacket(socket, answer, extra, 15000);
            if (extra >= 0) ::close(extra);
            const auto restored = dns.restore(device, checkpoint);
            success(restored); success(result);
            check(extra < 0 && answer["done"] == true, "DNS flow fixture lost its acknowledgement");
            std::cout << "PASS: actual ordinary system resolver used the owned TUN DNS path\n"; return 0;
        }
        success(dns.restore(device, checkpoint));
        throw std::runtime_error("Requested real DNS checkpoint was never reached");
    }
    check(argc == 2 && app.arguments()[1] == "--isolated", "Unknown native DNS fixture mode");
    const auto original = settings("dnsoriginal0");
    const auto owner = QUuid::createUuid(); UnixTunDevice device; create(device, owner);
    LinuxTunDns offline(QDBusConnection("missing-owned-dns-test"));
    const auto unavailable = offline.apply(device, {"campus.test"});
    check(!unavailable.succeeded() && !unavailable.mayHaveChanged && offline.snapshot().isEmpty(),
          "Unavailable resolver modified DNS or retained a false applied state");
    LinuxTunDns dns(bus);
    for (const auto &names : QList<QStringList>{{}, {"."}, {"Campus.test"}, {"-bad.test"}, {"a..test"}, {"campus.test", "campus.test"}})
        check(!dns.apply(device, names).succeeded() && dns.snapshot().isEmpty(), "Invalid routing domains changed DNS");
    QTemporaryDir directory; check(directory.isValid(), "Private DNS journal directory");
    UnixNetworkJournal journal; openJournal(journal, directory.path(), owner);
    success(dns.apply(device, {"campus.test", "research.test"}, writer(journal)));
    const auto configured = settings(device.name());
    check(configured[0].endsWith(": 198.18.0.2") && configured[1].contains("~campus.test")
        && configured[1].contains("~research.test") && configured[2].endsWith(": no"), "Actual link DNS/routing/default scope differs");
    const auto saved = dns.snapshot();
    check(!dns.apply(device, {"other.test"}).succeeded() && dns.snapshot() == saved, "Active DNS operation was replaced");
    for (const auto *field : {"owner", "namespace", "interface", "index", "provider", "before", "applied", "pending", "released"}) {
        auto bad = saved; bad[field] = QJsonValue::Null; LinuxTunDns rejected(bus);
        check(!rejected.recover(owner, bad).succeeded() && rejected.snapshot().isEmpty(), "Invalid DNS ownership accepted");
    }
    for (int kind = 0; kind < 3; ++kind) {
        auto bad = saved;
        if (kind < 2) {
            bad["pending"] = kind == 0 ? saved["applied"] : saved["before"];
            bad["restoring"] = kind == 1;
        } else {
            auto invalid = saved["applied"].toObject(); invalid["default_route"] = true; bad["applied"] = invalid;
        }
        LinuxTunDns rejected(bus);
        check(!rejected.recover(owner, bad).succeeded() && rejected.snapshot().isEmpty() && settings(device.name()) == configured,
              "Malformed DNS transition reached the resolver or retained authority");
    }
    resolver({"domain", device.name(), "~external.test"});
    const auto external = settings(device.name());
    bool failedCleanup = false;
    const auto released = dns.restore(device, [&](const QJsonObject &record) {
        if (record.isEmpty() && !failedCleanup) {
            failedCleanup = true; return Result{Status::Failed, "Injected final DNS receipt removal failure"};
        }
        return writer(journal)(record);
    });
    check(!released.succeeded() && failedCleanup && dns.snapshot()["released"] == true && settings(device.name()) == external,
          "External DNS ownership was overwritten or lost after receipt removal failed");
    resolver({"domain", device.name(), "~campus.test", "~research.test"});
    const auto recreated = settings(device.name());
    success(dns.restore(device, writer(journal)));
    check(settings(device.name()) == recreated && dns.snapshot().isEmpty(), "Receipt retry reclaimed externally recreated identical DNS settings");
    resolver({"revert", device.name()});
    const auto baseline = settings(device.name());
    bool blocked = false;
    const auto partial = dns.apply(device, {"campus.test"}, [&](const QJsonObject &record) {
        if (!blocked && record["pending"].toObject()["dns"].toArray().size() == 1) {
            blocked = true; return Result{Status::Failed, "Injected failure before DNS publication"};
        }
        return writer(journal)(record);
    });
    check(blocked && !partial.succeeded() && !partial.mayHaveChanged && dns.snapshot().isEmpty()
        && settings(device.name()) == baseline, "Partial DNS setup failed to restore its original native state");
    success(dns.apply(device, {"campus.test"}, writer(journal)));
    journal.close();
    const auto recovered = runPlatformCommand(app.applicationFilePath(), {"--recover-isolated", directory.path(), owner.toString(QUuid::WithoutBraces)}, 10000);
    success(recovered.result);
    check(settings(device.name()) == baseline && settings("dnsoriginal0") == original,
          "Fresh DNS recovery changed another interface or lost the original owned settings");
    std::cout << "PASS: actual per-link DNS, external preservation, partial rollback and fresh-process journal recovery\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n'; return 1;
}
