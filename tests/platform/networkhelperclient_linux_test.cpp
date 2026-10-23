#include "infrastructure/platform/linux/networkhelperclient.h"
#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QFileInfo>
#include <QJsonDocument>
#include <QThread>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unistd.h>

using Client = LinuxNetworkHelperClient;
using Status = PlatformOperationResult::Status;
static void check(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
template<class Predicate> static void wait(Predicate predicate, int timeoutMs = 10000)
{
    QDeadlineTimer deadline(timeoutMs);
    while (!predicate() && !deadline.hasExpired()) { QCoreApplication::processEvents(); QThread::msleep(1); }
    check(predicate(), "Client operation did not complete within its test budget");
}

int main(int argc, char **argv) try
{
    QCoreApplication app(argc, argv);
    check(::getuid() == ::geteuid() && ::getuid() != 0, "Qt network host retained privilege");
    auto client = std::make_unique<Client>();
    QList<PlatformOperationResult> results;
    QList<PlatformOperationResult> lost;
    QObject::connect(client.get(), &Client::finished, &app, [&](Client::Operation, PlatformOperationResult result) { results.append(result); });
    QObject::connect(client.get(), &Client::ownershipLost, &app, [&](PlatformOperationResult result) { lost.append(result); });
    if (argc == 1) {
        client->apply(QUuid::createUuid(), {});
        client->recover({});
        check(results.size() == 2 && !results[0].succeeded() && !results[1].succeeded()
            && client->state() == Client::State::Idle, "Invalid configuration reached authorization");
        std::cout << "PASS: invalid typed input rejected before deployment inspection or authorization\n";
        return 0;
    }
    const auto arguments = app.arguments();
    check(arguments.size() == 3, "Expected native scenario and connection UUID");
    const auto scenario = arguments[1];
    const QUuid owner(arguments[2]);
    check(!owner.isNull(), "Invalid native owner");
    int heartbeats = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, &app, [&] { ++heartbeats; });
    heartbeat.start(1);
    QObject::connect(client.get(), &Client::stateChanged, &app, [&](Client::State state) {
        if ((scenario == "cancel-inspect" && state == Client::State::Inspecting)
            || (scenario == "cancel-apply" && state == Client::State::Applying)) client->cancel();
        if (scenario == "cancel-authorization" && state == Client::State::Authorizing)
            QTimer::singleShot(50, client.get(), &Client::cancel);
    });
    LinuxHelperConfiguration configuration;
    configuration.address = "198.18.0.1"; configuration.peer = "198.18.0.2"; configuration.mtu = 1400;
    configuration.capturePrefixes = {"198.18.4.0/24"};
    if (scenario == "partial") configuration.capturePrefixes = {"198.18.5.0/24"};
    configuration.originalInterface = "helperorig0"; configuration.originalSource = "192.0.2.1";
    configuration.originalPrefixes = configuration.capturePrefixes;
    if (scenario == "cleanup") client->cleanupRestored(owner);
    else if (scenario == "recover") client->recover(owner);
    else client->apply(owner, configuration);
    wait([&] { return !results.isEmpty(); });
    if (scenario.startsWith("cancel-") || scenario == "denied" || scenario == "malformed" || scenario == "partial" || scenario == "guard-blocked") {
        const auto expected = scenario == "guard-blocked" ? Status::Unsupported : scenario == "denied" ? Status::PermissionDenied
            : scenario == "malformed" || scenario == "partial" ? Status::Failed : Status::Cancelled;
        check(results[0].status == expected, "Authorization/cancellation response was misclassified");
        check(client->state() == (scenario == "malformed" ? Client::State::RecoveryRequired : Client::State::Idle), "Wrong client recovery state");
        if (scenario == "cancel-authorization") check(heartbeats >= 5, "Authorization blocked the Qt event loop");
    } else {
        check(results[0].succeeded(), qPrintable(results[0].detail));
        if (scenario == "cleanup" || scenario == "recover") check(client->state() == Client::State::Idle, "Recovery did not finish receipt cleanup");
        else {
            check(client->state() == Client::State::Active && client->descriptor() >= 0, "No active borrowed TUN descriptor");
            QProcess exchange;
            const int device = client->descriptor();
            exchange.setChildProcessModifier([device] { ::fcntl(device, F_SETFD, 0); });
            exchange.start("/usr/bin/python3", {"-B", "-c",
                "import sys;sys.path.insert(0,sys.argv[1]);from unix_device_probe import exchange;exchange(int(sys.argv[2]),'198.18.4.7')",
                QFileInfo(QString::fromUtf8(__FILE__)).absolutePath(), QString::number(device)});
            check(exchange.waitForFinished(8000) && exchange.exitCode() == 0 && exchange.exitStatus() == QProcess::NormalExit,
                qPrintable(QString::fromUtf8(exchange.readAllStandardError())));
            if (scenario == "managed") {
                std::cout << "READY: managed helper " << owner.toString(QUuid::WithoutBraces).toStdString() << std::endl;
                wait([] { return false; }, 30000);
            } else if (scenario == "crash") {
                std::cout << "READY: active helper " << owner.toString(QUuid::WithoutBraces).toStdString() << std::endl;
                wait([&] { return !lost.isEmpty(); });
                check(lost.size() == 1 && !lost[0].succeeded() && lost[0].mayHaveChanged
                    && client->state() == Client::State::RecoveryRequired && client->descriptor() == -1,
                    "Helper loss did not revoke its descriptor and retain recovery responsibility");
                client->restore();
                wait([&] { return results.size() == 2; });
                check(results[1].succeeded() && client->state() == Client::State::Idle, "Fresh Qt-authorized recovery failed");
            } else if (scenario == "destroy") {
                client.reset();
                QDeadlineTimer settle(200);
                while (!settle.hasExpired()) { QCoreApplication::processEvents(); QThread::msleep(1); }
            } else {
                client->restore();
                wait([&] { return results.size() == 2; });
                check(results[1].succeeded() && client->state() == Client::State::Idle && client->descriptor() == -1,
                    "Restore reported completion before its descriptor and receipt were released");
            }
        }
    }
    std::cout << "PASS: Qt helper client " << scenario.toStdString() << '\n';
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
