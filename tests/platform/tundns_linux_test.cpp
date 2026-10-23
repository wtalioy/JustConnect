#include "infrastructure/platform/linux/tundns.h"
#include "infrastructure/platform/linux/iprouteutility.h"
#include "infrastructure/platform/linux/networkhelper.h"
#include "infrastructure/platform/linux/sourcejournal.h"
#include "infrastructure/platform/platformcommand.h"
#include <QCoreApplication>
#include <QDBusConnection>
#include <QTemporaryDir>
#include <csignal>
#include <fcntl.h>
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
    for (const auto *kind : {"net", "mnt"}) {
        struct stat here{}, host{};
        const auto suffix = QByteArray("/ns/") + kind;
        check(::stat(("/proc/thread-self" + suffix).constData(), &here) == 0
            && ::stat(("/proc/1" + suffix).constData(), &host) == 0
            && (here.st_dev != host.st_dev || here.st_ino != host.st_ino), "Refusing host network or mounts");
    }
    struct stat socket{}, host{};
    check(::stat("/run/dbus/system_bus_socket", &socket) == 0 && S_ISSOCK(socket.st_mode) && socket.st_uid == 0,
          "A private root-owned resolver bus is required");
    check(::stat("/proc/1/root/run/dbus/system_bus_socket", &host) != 0
        || socket.st_dev != host.st_dev || socket.st_ino != host.st_ino, "Refusing the host system bus");
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
static LinuxTunDns::CheckpointWriter writer(LinuxSourceJournal &journal)
{
    return [&journal](const QJsonObject &value) { return value.isEmpty() ? journal.remove() : journal.store(value); };
}
static void openJournal(LinuxSourceJournal &journal, const QString &path, const QUuid &owner)
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
        std::cout << "PASS: ordinary DNS mutation and unowned recovery rejected\n";
        return 0;
    }
    const auto bus = privateBus();
    if (argc == 2 && app.arguments()[1] == "--absent-isolated") {
        UnixTunDevice device; create(device, QUuid::createUuid());
        LinuxTunDns dns(bus); const auto result = dns.apply(device, {"campus.test"});
        check(result.status == Status::Unsupported && !result.mayHaveChanged && dns.snapshot().isEmpty(),
              "Absent resolver was misclassified or modified the owned DNS state");
        std::cout << "PASS: absent resolver reports unsupported without starting a service or changing DNS\n"; return 0;
    }
    if (argc == 4 && app.arguments()[1] == "--recover-isolated") {
        const QUuid owner(app.arguments()[3]); LinuxSourceJournal journal;
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
        LinuxSourceJournal journal; openJournal(journal, app.arguments()[3], owner);
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
    LinuxSourceJournal journal; openJournal(journal, directory.path(), owner);
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
