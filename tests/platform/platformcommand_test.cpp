#include "infrastructure/process/command.h"
#include <QCoreApplication>
#include <QThread>
#include <cstdio>
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains("--environment")) {
        check(qEnvironmentVariable("JC_COMMAND_TEST_INSIDE") == "visible"
            && !qEnvironmentVariableIsSet("JC_COMMAND_TEST_OUTSIDE"), "A privileged command inherited an unintended environment");
        return 0;
    }
    if (app.arguments().size()>1) {
        if (app.arguments()[1]=="--denied") { std::cerr << "Operation not permitted\n"; return 1; }
        std::cerr << "private diagnostic\nJCDNS phase=nrpt elapsed_ms=123\n" << std::flush;
        std::cout << "partial" << std::flush;
        if (app.arguments()[1]=="--hang") QThread::sleep(5);
        return 7;
    }
    using Status = PlatformOperationResult::Status;
    qputenv("JC_COMMAND_TEST_OUTSIDE", "hidden");
    auto isolated = QProcessEnvironment::systemEnvironment();
    isolated.remove("JC_COMMAND_TEST_OUTSIDE");
    isolated.insert("JC_COMMAND_TEST_INSIDE", "visible");
    check(runPlatformCommand(app.applicationFilePath(), {"--environment"}, 2000, isolated).result.succeeded(),
        "Explicit command environment failed to isolate inherited variables");
    check(runPlatformCommand(app.applicationFilePath(), {"--denied"}).result.status == Status::PermissionDenied,
          "Kernel operation permission denial lost its classification");
    const auto failed = runPlatformCommand(app.applicationFilePath(), {"--fail"});
    check(failed.result.status==Status::Failed && failed.standardError.contains("JCDNS phase=nrpt")
          && !failed.result.detail.contains("private diagnostic"), "Failed command lost stderr or exposed it as a public error");
    const auto timed = runPlatformCommand(app.applicationFilePath(), {"--hang"}, 2000);
    check(timed.result.status==Status::TimedOut && timed.output.isEmpty()
          && timed.standardError.contains("JCDNS phase=nrpt"), "Timed out command lost partial stderr or published partial stdout");
    std::cout << "PASS: exit and timeout preserve private stderr without publishing partial results\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
