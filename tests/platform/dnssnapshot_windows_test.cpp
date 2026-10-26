#include "infrastructure/dns/windows/dnssnapshot.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains("--native") || app.arguments().contains("--system-library")
        || app.arguments().contains("--missing-doh") || app.arguments().contains("--missing-nrpt")
        || app.arguments().contains("--empty-nrpt") || app.arguments().contains("--timeout")) {
        const bool scope = app.arguments().contains("--system-library");
        const bool missing = app.arguments().contains("--missing-doh");
        const bool missingNrpt = app.arguments().contains("--missing-nrpt");
        const bool emptyNrpt = app.arguments().contains("--empty-nrpt");
        const bool timeout = app.arguments().contains("--timeout");
        QTemporaryDir directory;
        PlatformCommandRunner runner;
        const auto program = qEnvironmentVariable("JC_TEST_WINDOWS_DNS_READER");
        if (!program.isEmpty() || scope || missing || missingNrpt || emptyNrpt || timeout) runner = [&](const QString &nativeProgram, const QStringList &arguments) {
            auto modified = arguments;
            if (missing) modified.append("--missing-doh");
            if (missingNrpt) modified.append("--missing-nrpt");
            if (emptyNrpt) modified.append("--empty-nrpt");
            if (timeout) modified.append("--stall");
            const bool fixture = missing || missingNrpt || emptyNrpt || timeout;
            const auto executable = !program.isEmpty() ? program : fixture
                ? QDir(QCoreApplication::applicationDirPath()).filePath("windows_dnsreader_test.exe") : nativeProgram;
            if (scope) {
                const auto copy = directory.filePath("JustConnectDnsReader.exe");
                check(directory.isValid() && QFile::copy(executable, copy), "Copy the native reader into a private library fixture");
                check(QFile::setPermissions(copy, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner), "Set private reader permissions");
                QFile foreign(directory.filePath("mi.dll"));
                const QByteArray poison("Invalid foreign MI library; must never be loaded.");
                check(foreign.open(QIODevice::WriteOnly) && foreign.write(poison) == poison.size(), "Write the foreign MI library fixture");
                foreign.close();
                return runPlatformCommand(copy, modified, 10000);
            }
            return runPlatformCommand(executable, modified, timeout ? 1000 : 10000);
        };
        const auto snapshot = runner ? readWindowsDnsSnapshot(runner) : readSystemDnsSnapshot();
        if (timeout) {
            check(snapshot.result.status == PlatformOperationResult::Status::TimedOut && snapshot.data.isEmpty(),
                  "Stalled native DNS reader escaped the deadline or published partial facts");
            std::cout << "Stalled native DNS process stopped without a partial snapshot\n";
            return 0;
        }
        if (missingNrpt) {
            check(!snapshot.result.succeeded() && snapshot.data.isEmpty(), "Missing required provider published partial DNS facts");
            std::cout << "Required native resolver provider failure rejected without partial data\n";
            return 0;
        }
        check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
        check(!snapshot.data["interfaces"].toArray().isEmpty(), "Native DNS interface facts missing");
        if (missing) check(snapshot.data["doh_supported"] == false && snapshot.data["doh"].toArray().isEmpty(),
                           "Missing optional DNS provider did not remain unavailable");
        if (emptyNrpt) check(snapshot.data["nrpt"].toArray().isEmpty(), "Successful empty NRPT provider result became an error or partial policy");
        std::cout << "Native resolver interfaces, effective NRPT and DoH registrations inspected without writes\n";
        return 0;
    }
    auto data = QJsonDocument::fromJson(R"JSON({
        "interfaces":[{"InterfaceIndex":7,"AddressFamily":23,"ServerAddresses":["2001:db8::53"]}],
        "clients":[{"InterfaceIndex":7,"ConnectionSpecificSuffix":"overlay.test","ConnectionSpecificSuffixSearchList":["overlay.test"]}],
        "global":{"SuffixSearchList":[]},
        "nrpt":[{"Namespace":[".overlay.test"],"NameServers":["192.0.2.53"],"DirectAccessEnabled":false,"DirectAccessDnsServers":[],"QueryPolicy":"QueryIPv6Only","SecureNameQueryFallback":"Disable","DnsSecValidationRequired":null}],
        "doh_supported":false,"doh":[]
    })JSON").object();
    PlatformOperationResult result;
    QString output;
    auto runner = [&](const QString &, const QStringList &arguments) {
        check(arguments.isEmpty(), "Native read-only DNS reader gained arbitrary query arguments");
        return PlatformCommandResult{result, output};
    };
    output = QString::fromUtf8(QJsonDocument(data).toJson());
    const auto snapshot = readWindowsDnsSnapshot(runner);
    check(snapshot.result.succeeded() && snapshot.data == data, "DNS source identity or NRPT security properties lost");
    for (const auto status : {PlatformOperationResult::Status::PermissionDenied, PlatformOperationResult::Status::TimedOut}) {
        result.status = status;
        const auto denied = readWindowsDnsSnapshot(runner);
        check(denied.result.status == status && denied.data.isEmpty(), "Failed command published partial facts");
    }
    result = {};
    result.status = PlatformOperationResult::Status::TimedOut;
    for (const auto &stage : {QString("nrpt"), QString("native"), QString("nrpt_sources"), QString("nrpt_consistency")}) {
        auto traced = [&](const QString &p, const QStringList &a) {
            auto command = runner(p,a);
            command.standardError = "private.campus.test\nJCDNS phase=" + stage + " elapsed_ms=321\nJCDNS phase=privatecorp elapsed_ms=999\n";
            return command;
        };
        const auto timed = readWindowsDnsSnapshot(traced);
        check(timed.result.status==result.status && timed.data.isEmpty() && timed.result.detail.contains(stage+" at 321 ms")
              && !timed.result.detail.contains("private"), "Timeout lost its safe native/CIM phase or exposed raw diagnostics");
    }
    result = {};
    for (const auto &invalid : {QString("{}"), QString("warning\n") + output, QString(262145, 'x')}) {
        output = invalid;
        const auto bad = readWindowsDnsSnapshot(runner);
        check(!bad.result.succeeded() && bad.data.isEmpty(), "Malformed or excessive output accepted");
    }
    auto policies = data["nrpt"].toArray();
    auto policy = policies[0].toObject();
    policy["NameServers"] = "192.0.2.53";
    policies[0] = policy; data["nrpt"] = policies;
    output = QString::fromUtf8(QJsonDocument(data).toJson());
    check(!readWindowsDnsSnapshot(runner).result.succeeded(), "Collapsed native singleton array accepted");
    std::cout << "Resolver facts, NRPT policy preservation and failure boundaries passed\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
