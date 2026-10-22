#include "infrastructure/platform/windows/dnssnapshot.h"
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
    if (app.arguments().contains("--native") || app.arguments().contains("--module-scope")) {
        const bool scope = app.arguments().contains("--module-scope");
        QTemporaryDir directory;
        QString moduleRoot;
        if (scope) {
            check(directory.isValid() && QDir(directory.path()).mkdir("JustConnectDnsFixture"), "Create private module fixture");
            for (const auto &file : {QString("JustConnectDnsFixture.psd1"), QString("fixture.psm1")}) {
                QFile output(directory.filePath("JustConnectDnsFixture/" + file));
                const auto content = file.endsWith("psd1")
                    ? QByteArray("@{RootModule='fixture.psm1';ModuleVersion='1.0';FunctionsToExport=@('Get-JustConnectUnimportedDnsFeature')}")
                    : QByteArray("function Get-JustConnectUnimportedDnsFeature {}\n");
                check(output.open(QIODevice::WriteOnly) && output.write(content) == content.size(), "Write private module fixture");
            }
            moduleRoot = directory.path();
#ifndef Q_OS_WIN
            const auto path = runPlatformCommand("wslpath", {"-w", moduleRoot});
            check(path.result.succeeded(), "Map private module fixture for Windows interop");
            moduleRoot = path.output;
#endif
        }
        PlatformCommandRunner runner;
        const auto program = qEnvironmentVariable("JC_TEST_WINDOWS_POWERSHELL");
        if (!program.isEmpty() || scope) runner = [&](const QString &nativeProgram, const QStringList &arguments) {
            auto modified = arguments;
            if (scope) {
                // Permit this test process to load its private unsigned fixture module.
                modified = QStringList{"-ExecutionPolicy", "Bypass"} + modified;
                modified.last().replace("Get-Command Get-DnsClientDohServerAddress", "Get-Command Get-JustConnectUnimportedDnsFeature");
                modified.last().prepend("$env:PSModulePath='" + QString(moduleRoot).replace("'", "''")
                    + "'+[IO.Path]::PathSeparator+$env:PSModulePath\n");
            }
            return runPlatformCommand(program.isEmpty() ? nativeProgram : program, modified, 10000);
        };
        const auto snapshot = runner ? readWindowsDnsSnapshot(runner) : readSystemDnsSnapshot();
        check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
        check(!snapshot.data["interfaces"].toArray().isEmpty(), "Native DNS interface facts missing");
        if (scope) check(snapshot.data["doh_supported"] == false && snapshot.data["doh"].toArray().isEmpty(),
                         "Optional DNS discovery imported a foreign module");
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
        check(arguments.size() == 5 && arguments[0] == "-NoLogo" && arguments[1] == "-NoProfile"
              && arguments[2] == "-NonInteractive" && arguments[3] == "-Command"
              && arguments[4].contains("Get-DnsClientNrptPolicy -Effective")
              && !arguments[4].contains("Set-DnsClient"), "Fixed read-only system query changed");
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
    check(!readWindowsDnsSnapshot(runner).result.succeeded(), "Collapsed PowerShell singleton array accepted");
    std::cout << "Resolver facts, NRPT policy preservation and failure boundaries passed\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
