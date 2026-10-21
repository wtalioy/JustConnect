#include "infrastructure/platform/windows/dnssnapshot.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <iostream>
#include <cstdlib>

static void check(bool ok, const char *message) {
    if (!ok) { std::cerr << message << '\n'; std::exit(1); }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains("--native")) {
        PlatformCommandRunner runner;
        const auto program = qEnvironmentVariable("JC_TEST_WINDOWS_POWERSHELL");
        if (!program.isEmpty()) runner = [&](const QString &, const QStringList &arguments) {
            return runPlatformCommand(program, arguments, 10000);
        };
        const auto snapshot = readWindowsDnsSnapshot(runner);
        check(snapshot.result.succeeded(), qPrintable(snapshot.result.detail));
        check(!snapshot.data["interfaces"].toArray().isEmpty(), "Native DNS interface facts missing");
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
}
