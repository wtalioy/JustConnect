#include "infrastructure/platform/macos/tunroutes.h"
#include "infrastructure/platform/ipv4.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QTemporaryDir>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static QJsonArray routes(const QString &prefix)
{
    const auto current = readMacRoutes();
    check(current.result.succeeded(), qPrintable(current.result.detail));
    QJsonArray result;
    for (const auto &entry : current.rows) if (entry.toObject()["prefix"] == prefix) result.append(entry);
    return result;
}
static void nativeChange(const QString &operation, const QString &prefix, const QString &interface, const QStringList &extra = {})
{
    QStringList args{"-n", operation, "-inet", "-net", prefix, "-interface", interface};
    args += extra;
    const auto result = runPlatformCommand("/sbin/route", args, 5000, {}, QProcessEnvironment{});
    check(result.result.succeeded(), qPrintable(result.result.detail+result.standardError));
}
static void journalBoundary(int directory, const QString &path, const QUuid &owner)
{
    UnixNetworkJournal journal;
    check(journal.open(directory, owner).succeeded(), "Open the root-private journal");
    UnixNetworkJournal duplicate;
    bool active = false;
    check(!duplicate.open(directory, owner, &active).succeeded() && active, "Independent guardian obtained the same lock");
    const QJsonObject record{{"owner", owner.toString(QUuid::WithoutBraces)}, {"state", 1}};
    check(journal.store(record).succeeded(), "Publish the first native exclusive checkpoint");
    QJsonObject loaded;
    check(journal.load(loaded).succeeded() && loaded == record, "Load the complete native checkpoint");
    struct stat metadata{};
    check(::lstat(QFile::encodeName(path).constData(), &metadata) == 0 && metadata.st_uid == 0
        && (metadata.st_mode & 07777) == 0600 && metadata.st_nlink == 1, "Unsafe native checkpoint metadata");
    auto next = record; next["state"] = 2;
    check(journal.store(next).succeeded() && journal.load(loaded).succeeded() && loaded == next, "Replace and synchronize the accepted checkpoint");
    check(::chmod(QFile::encodeName(path).constData(), 0644) == 0 && !journal.load(loaded).succeeded()
        && loaded.isEmpty() && !journal.remove().succeeded(), "Unsafe checkpoint file was read or removed");
    check(::chmod(QFile::encodeName(path).constData(), 0600) == 0, "Restore checkpoint mode");
    const auto replacement = path+".external";
    QFile copy(replacement);
    check(copy.open(QIODevice::WriteOnly) && copy.write(QJsonDocument(next).toJson(QJsonDocument::Compact)) > 0, "Create external same-value checkpoint");
    copy.close();
    check(::chmod(QFile::encodeName(replacement).constData(),0600) == 0
        && ::rename(QFile::encodeName(replacement).constData(),QFile::encodeName(path).constData()) == 0
        && !journal.remove().succeeded() && !journal.store(next).succeeded(), "Same-value replacement was adopted");
    journal.close();
    check(journal.open(directory, owner).succeeded() && journal.load(loaded).succeeded() && journal.remove().succeeded(), "Explicit fresh guardian cannot recover accepted storage");
    check(journal.remove().succeeded(), "Native journal cleanup is not idempotent");
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    const auto initial = readMacRoutes();
    check(initial.result.succeeded() && !macBootSession().isEmpty(), "Read complete native routing and boot identity");
    if (argc == 1) {
        check(::geteuid() != 0, "Ordinary boundary check must not run as root");
        UnixNetworkJournal journal;
        check(journal.open(AT_FDCWD, QUuid::createUuid()).status == PlatformOperationResult::Status::PermissionDenied,
            "Ordinary caller gained privileged journal authority");
        UnixTunDevice device; MacTunRoutes capture;
        check(!capture.apply(device, {"198.18.0.6/32"}).succeeded() && capture.snapshot().isEmpty(), "Unowned device gained capture authority");
        return 0;
    }
    check(::geteuid() == 0 && qgetenv("GITHUB_ACTIONS") == "true" && qgetenv("RUNNER_OS") == "macOS",
        "Native network changes require the disposable macOS runner");
    if (argc == 4 && app.arguments()[1] == "--recover") {
        const int directory = ::open(QFile::encodeName(app.arguments()[2]).constData(), O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        const QUuid owner(app.arguments()[3]); UnixNetworkJournal journal; QJsonObject saved;
        check(directory >= 0 && journal.open(directory, owner).succeeded() && journal.load(saved).succeeded(), "Load authenticated new-process ownership");
        MacTunRoutes recovery;
        const auto result = recovery.recover(owner, saved, [&](const QJsonObject &record) { return record.isEmpty() ? journal.remove() : journal.store(record); });
        check(result.succeeded(), qPrintable(result.detail));
        ::close(directory); return 0;
    }
    check(argc == 2 && app.arguments()[1] == "--isolated", "Unknown native route fixture mode");
    for (const auto &value : initial.rows) {
        const auto prefix = value.toObject()["prefix"].toString();
        if (!canonicalIpv4Prefix(prefix)) continue;
        for (const auto *address : {"198.18.0.1", "198.18.0.2", "198.18.0.6", "198.18.1.1"})
            check(!ipv4PrefixContainsAddress(prefix, QString::fromLatin1(address)), "The fixture address range already belongs to an existing route");
    }
    QTemporaryDir temporary; check(temporary.isValid(), "Create root-private ownership directory");
    const int directory = ::open(QFile::encodeName(temporary.path()).constData(), O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    check(directory >= 0 && ::fchmod(directory,0700) == 0, "Open private native storage");
    const auto owner = QUuid::createUuid(); const auto path = temporary.filePath("source.json");
    journalBoundary(directory, path, owner);
    UnixNetworkJournal journal;
    check(journal.open(directory, owner).succeeded(), "Open actual route checkpoints");
    const auto checkpoint = [&](const QJsonObject &record) { return record.isEmpty() ? journal.remove() : journal.store(record); };
    const auto recoverInNewProcess = [&] {
        journal.close();
        QProcess recovery;
        auto environment = QProcessEnvironment::systemEnvironment();
        recovery.setProcessEnvironment(environment);
        recovery.start(QCoreApplication::applicationFilePath(), {"--recover", temporary.path(), owner.toString(QUuid::WithoutBraces)});
        check(recovery.waitForStarted(5000) && recovery.waitForFinished(15000) && recovery.exitCode() == 0,
            qPrintable(QString::fromUtf8(recovery.readAllStandardError())));
        check(journal.open(directory,owner).succeeded(), "Reopen storage after independent recovery");
    };
    UnixTunDevice device;
    const auto configured = device.createIpv4(owner,"198.18.0.1","198.18.0.2",1400);
    check(configured.succeeded(),qPrintable(configured.detail));
    const QString first("198.18.0.6/32"), second("198.18.1.0/24");
    {
        MacTunRoutes capture;
        for (const auto &bad : {QString("0.0.0.0/0"), QString("198.18.0.7/31"), QString("198.18.0.6/032"), QString("198.18.0.1/32"), QString("127.0.0.1/32"), QString("224.0.0.0/4")})
            check(!capture.apply(device,{bad},checkpoint).succeeded() && capture.snapshot().isEmpty() && !QFile::exists(path), "Invalid or self-capturing prefix reached the kernel");
        const auto applied = capture.apply(device,{first,first,second},checkpoint);
        if (!applied.succeeded()) std::cerr << QJsonDocument(readMacRoutes().rows).toJson().constData();
        check(applied.succeeded(),qPrintable(applied.detail));
        check(capture.snapshot()["routes"].toArray().size() == 2 && routes(first).size() == 1 && routes(second).size() == 1, "Applied captures differ from their ownership record");
        const auto lookup = runPlatformCommand("/sbin/route", {"-n","get","198.18.1.1"},5000,{},QProcessEnvironment{});
        check(lookup.result.succeeded() && lookup.output.contains("interface: "+device.name()), "The actual subnet destination did not select the owned utun");
        check(capture.extend(device,{"198.18.0.7","198.18.0.7","198.18.1.1"},checkpoint).succeeded()
            && capture.snapshot()["routes"].toArray().size() == 3 && routes("198.18.0.7/32").size() == 1,
            "DNS extension was not confirmed or duplicated an already covered subnet");
        const auto extended = capture.snapshot();
        check(!capture.extend(device,{"198.18.0.1"},checkpoint).succeeded() && capture.snapshot() == extended,
            "DNS extension captured its own source or changed confirmed ownership");
        const auto unchanged = capture.extend(device,{"198.18.0.7","198.18.1.1"},checkpoint);
        check(unchanged.succeeded() && !unchanged.mayHaveChanged && capture.snapshot() == extended,"Repeated DNS addresses mutated existing capture");
        const auto before = routes(first);
        check(!capture.restore(QUuid::createUuid(),checkpoint).succeeded() && routes(first) == before, "Another owner removed actual capture");
        auto damaged = capture.snapshot();
        damaged["boot"] = QUuid::createUuid().toString(QUuid::WithoutBraces);
        MacTunRoutes foreignBoot;
        check(!foreignBoot.recover(owner,damaged,checkpoint).succeeded() && routes(first) == before, "Another boot's record gained route authority");
        damaged = capture.snapshot(); auto damagedRows = damaged["routes"].toArray(); auto damagedRow = damagedRows[0].toObject();
        auto incomplete = damagedRow["applied"].toObject(); incomplete.remove("metrics");
        damagedRow["applied"] = incomplete; damagedRows[0] = damagedRow; damaged["routes"] = damagedRows;
        MacTunRoutes incompleteOwner;
        check(!incompleteOwner.recover(owner,damaged,checkpoint).succeeded() && routes(first) == before, "Incomplete native route identity was accepted");
        recoverInNewProcess();
        check(routes(first).isEmpty() && routes(second).isEmpty() && routes("198.18.0.7/32").isEmpty() && !QFile::exists(path)
            && ::if_nametoindex(device.name().toLatin1().constData()) == device.index(), "Independent recovery lost device identity or retained capture");
    }
    {
        MacTunRoutes capture;
        check(capture.apply(device,{first},checkpoint).succeeded(),"Prepare conflicting DNS publication");
        nativeChange("add","198.18.0.7/32",device.name()); const auto external = routes("198.18.0.7/32");
        const auto owned = capture.snapshot();
        check(!capture.extend(device,{"198.18.0.7"},checkpoint).succeeded() && capture.snapshot() == owned
            && routes("198.18.0.7/32") == external,"DNS publication adopted an external exact-prefix route");
        check(capture.restore(owner,checkpoint).succeeded() && routes("198.18.0.7/32") == external,"Connection rollback removed an external DNS route");
        nativeChange("delete","198.18.0.7/32",device.name());
    }
    {
        int additions = 0;
        MacTunRoutes capture([&](const QString &program,const QStringList &arguments) {
            if (arguments.contains("add") && ++additions == 3) return PlatformCommandResult{{PlatformOperationResult::Status::Failed,"injected extension failure"},{},{}};
            return runPlatformCommand(program,arguments,5000,{},QProcessEnvironment{});
        });
        check(capture.apply(device,{first},checkpoint).succeeded(),"Prepare partially applied DNS extension");
        check(!capture.extend(device,{"198.18.0.7","198.18.0.8"},checkpoint).succeeded()
            && routes("198.18.0.7/32").size() == 1,"DNS extension did not preserve its first real checkpoint after a later failure");
        recoverInNewProcess();
        check(routes(first).isEmpty() && routes("198.18.0.7/32").isEmpty() && routes("198.18.0.8/32").isEmpty()
            && !QFile::exists(path),"Fresh-process recovery retained partially appended DNS capture");
    }
    {
        nativeChange("add",first,device.name()); const auto foreign = routes(first);
        MacTunRoutes capture;
        check(!capture.apply(device,{first},checkpoint).succeeded() && routes(first) == foreign && !QFile::exists(path), "Existing exact-prefix route was overwritten");
        nativeChange("delete",first,device.name());
        check(capture.apply(device,{first},checkpoint).succeeded(), "Prepare external-edit capture");
        nativeChange("change",first,device.name(),{"-hopcount","7"}); const auto edited = routes(first);
        check(capture.restore(owner,checkpoint).succeeded() && routes(first) == edited && !QFile::exists(path), "Recovery overwrote an external metric change");
        nativeChange("delete",first,device.name());
    }
    {
        MacTunRoutes capture;
        check(capture.apply(device,{first},checkpoint).succeeded(), "Prepare shared-prefix capture");
        nativeChange("add",first,device.name(),{"-ifscope",device.name()});
        const auto both = routes(first);
        QJsonArray external;
        const auto owned = capture.snapshot()["routes"].toArray().first().toObject()["applied"].toObject();
        for (const auto &row : both) if (row.toObject() != owned) external.append(row);
        check(!external.isEmpty() && capture.restore(owner,checkpoint).succeeded() && routes(first) == external && !QFile::exists(path),
            "Recovery confused shared-prefix scope with ownership or removed an external scoped route");
        nativeChange("delete",first,device.name(),{"-ifscope",device.name()});
    }
    {
        int writes = 0; bool deny = true;
        MacTunRoutes capture([&](const QString &program, const QStringList &args) {
            ++writes; return runPlatformCommand(program,args,5000,{},QProcessEnvironment{});
        });
        const auto denied = capture.apply(device,{first},[&](const QJsonObject &record) {
            if (deny) { deny = false; return PlatformOperationResult{PlatformOperationResult::Status::PermissionDenied,"checkpoint denied"}; }
            return checkpoint(record);
        });
        check(denied.status == PlatformOperationResult::Status::PermissionDenied && !denied.mayHaveChanged && writes == 0
            && capture.snapshot().isEmpty() && routes(first).isEmpty() && !QFile::exists(path), "Denied intent publication reached kernel mutation");
    }
    {
        int adds = 0;
        MacTunRoutes capture([&](const QString &program, const QStringList &args) {
            if (args.contains("add") && ++adds == 2) return PlatformCommandResult{{PlatformOperationResult::Status::Failed,"injected second command failure"},{},{}};
            return runPlatformCommand(program,args,5000,{},QProcessEnvironment{});
        });
        check(!capture.apply(device,{first,second},checkpoint).succeeded() && capture.snapshot().isEmpty()
            && routes(first).isEmpty() && routes(second).isEmpty() && !QFile::exists(path), "Partial application did not roll back only its completed route");
    }
    {
        MacTunRoutes capture;
        check(capture.apply(device,{first},checkpoint).succeeded(), "Prepare interrupted capture fixture");
        auto saved = capture.snapshot(); auto list = saved["routes"].toArray(); auto route = list[0].toObject();
        route["delete_started"] = true; list[0] = route; saved["routes"] = list;
        check(journal.store(saved).succeeded(), "Publish actual interrupted deletion record");
        const auto before = routes(first); MacTunRoutes interrupted;
        check(!interrupted.recover(owner,saved,checkpoint).succeeded() && routes(first) == before && QFile::exists(path), "Interrupted matching route was adopted or deleted");
        route["delete_started"] = false; route["applied"] = QJsonObject{}; list[0] = route; saved["routes"] = list;
        check(journal.store(saved).succeeded(), "Publish actual unconfirmed application record");
        MacTunRoutes unconfirmed;
        check(!unconfirmed.recover(owner,saved,checkpoint).succeeded() && routes(first) == before, "Unconfirmed matching route was adopted or deleted");
        nativeChange("delete",first,device.name()); recoverInNewProcess();
        check(!QFile::exists(path), "Absent unconfirmed state retained stale ownership");
    }
    device.close(); journal.close(); ::close(directory);
    check(routes(first).isEmpty() && routes(second).isEmpty(), "Owned test capture survived final cleanup");
    std::cout << "PASS: native macOS capture, protected checkpoints, exact-route/metric preservation, partial failure, interrupted intent and independent recovery\n";
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
