#include "infrastructure/platform/linux/networkhelperclient.h"
#include "networkhelperfixture.h"
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
        client->extend({"198.18.6.7"});
        check(results.size() == 3 && !results[0].succeeded() && !results[1].succeeded() && !results[2].succeeded()
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
            || (scenario == "cancel-apply" && state == Client::State::Applying)
            || (scenario == "extend-cancel" && state == Client::State::Extending)) client->cancel();
        if (scenario == "cancel-authorization" && state == Client::State::Authorizing)
            QTimer::singleShot(50, client.get(), &Client::cancel);
    });
    auto configuration = helperFixtureConfiguration({scenario == "partial" ? "198.18.5.0/24" : "198.18.4.0/24"}, 1400);
    if (scenario.startsWith("dns")) configuration.dnsDomains = {"campus.test"};
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
            check(client->ownedConfiguration() && client->ownedDevice()["owner"] == owner.toString(QUuid::WithoutBraces),
                  "Active helper omitted its confirmed ownership view");
            const auto beforeExtension = *client->ownedConfiguration();
            QProcess exchange;
            const int device = client->descriptor();
            const int flags = ::fcntl(device, F_GETFL);
            check(flags >= 0 && (flags & O_NONBLOCK), "Borrowed TUN fd cannot provide interruptible core I/O");
            exchange.setChildProcessModifier([device] { ::fcntl(device, F_SETFD, 0); });
            exchange.start("/usr/bin/python3", {"-B", "-c",
                "import sys;sys.path.insert(0,sys.argv[1]);from unix_device_probe import exchange;exchange(int(sys.argv[2]),'198.18.4.7')",
                QFileInfo(QString::fromUtf8(__FILE__)).absolutePath(), QString::number(device)});
            check(exchange.waitForFinished(8000) && exchange.exitCode() == 0 && exchange.exitStatus() == QProcess::NormalExit,
                qPrintable(QString::fromUtf8(exchange.readAllStandardError())));
            auto previous = results.size();
            client->extend({"198.18.6.7"});
            wait([&] { return results.size() == previous+1; });
            if (scenario == "extend-cancel" || scenario == "extend-partial") {
                check(results.last().status == (scenario == "extend-cancel" ? Status::Cancelled : Status::Failed)
                      && client->state() == Client::State::Idle && client->descriptor() == -1,
                      "Failed/cancelled DNS publication did not restore and release its connection");
                check(!client->ownedConfiguration() && client->ownedDevice().isEmpty(), "Failed extension retained active ownership facts");
                std::cout << "PASS: Qt helper client " << scenario.toStdString() << '\n';
                return 0;
            }
            check(results.last().succeeded() && client->state() == Client::State::Active
                  && client->descriptor() == device && ::fcntl(device,F_GETFL) == flags,
                  "DNS publication replaced or closed the active borrowed descriptor");
            const auto extendedConfiguration = client->ownedConfiguration();
            check(extendedConfiguration && extendedConfiguration->capturePrefixes.contains("198.18.6.7/32")
                  && extendedConfiguration->originalPrefixes.contains("198.18.6.7/32")
                  && extendedConfiguration->capturePrefixes.size() == beforeExtension.capturePrefixes.size() + 1,
                  "Acknowledged DNS publication was not added to its owned view");
            previous = results.size();
            client->extend({"198.18.6.7"});
            wait([&] { return results.size() == previous+1; });
            check(results.last().succeeded() && !results.last().mayHaveChanged && client->descriptor() == device,
                  "Repeated DNS address publication changed active network state");
            check(client->ownedConfiguration()->capturePrefixes == extendedConfiguration->capturePrefixes,
                  "Repeated publication duplicated the ownership view");
            exchange.start("/usr/bin/python3", {"-B", "-c",
                "import sys;sys.path.insert(0,sys.argv[1]);from unix_device_probe import exchange;exchange(int(sys.argv[2]),'198.18.6.7')",
                QFileInfo(QString::fromUtf8(__FILE__)).absolutePath(),QString::number(device)});
            check(exchange.waitForFinished(8000) && exchange.exitCode() == 0 && exchange.exitStatus() == QProcess::NormalExit,
                  qPrintable(QString::fromUtf8(exchange.readAllStandardError())));
            if (scenario == "normal" || scenario == "routes-partial") {
                previous = results.size();
                const QStringList changedCapture{"198.18.4.0/24","198.18.7.0/24"};
                client->reconcile(changedCapture);
                wait([&] { return results.size() == previous+1; });
                if (scenario == "routes-partial") {
                    check(results.last().status == Status::Failed && client->state() == Client::State::Idle
                          && !client->ownedConfiguration() && client->descriptor() < 0,
                          "Partial live route apply failed to restore all owned network state");
                    std::cout << "PASS: Qt helper client " << scenario.toStdString() << '\n';
                    return 0;
                }
                check(results.last().succeeded() && client->state() == Client::State::Active && client->descriptor() == device
                      && client->ownedConfiguration()->capturePrefixes == changedCapture
                      && client->ownedConfiguration()->originalPrefixes.contains("198.18.6.7/32"),
                      "Live route confirmation replaced the fd or discarded still-owned original egress");
                previous = results.size();
                client->reconcile(beforeExtension.capturePrefixes);
                wait([&] { return results.size() == previous+1; });
                check(results.last().succeeded() && client->ownedConfiguration()->capturePrefixes == beforeExtension.capturePrefixes,
                      "Live route withdrawal retained stale capture in its confirmed view");
            }
            if (scenario.startsWith("dns")) {
                exchange.start("/usr/bin/python3", {"-B", "-c",
                    "import os,sys;sys.path.insert(0,sys.argv[1]);from tundns_fixture import query_via_tun;"
                    "query_via_tun(int(sys.argv[2]),sys.argv[3],sys.argv[4],os.getuid(),{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C.UTF-8'})",
                    QFileInfo(QString::fromUtf8(__FILE__)).absolutePath(), QString::number(device),
                    "helper-" + owner.toString(QUuid::Id128) + '.' + configuration.dnsDomains.first(), configuration.peer});
                check(exchange.waitForFinished(10000) && exchange.exitCode() == 0 && exchange.exitStatus() == QProcess::NormalExit,
                      qPrintable(QString::fromUtf8(exchange.readAllStandardError())));
            }
            if (scenario == "managed" || scenario == "dns-managed") {
                std::cout << "READY: managed helper " << owner.toString(QUuid::WithoutBraces).toStdString() << std::endl;
                wait([] { return false; }, 30000);
            } else if (scenario == "crash") {
                std::cout << "READY: active helper " << owner.toString(QUuid::WithoutBraces).toStdString() << std::endl;
                wait([&] { return !lost.isEmpty(); });
                check(lost.size() == 1 && !lost[0].succeeded() && lost[0].mayHaveChanged
                    && client->state() == Client::State::RecoveryRequired && client->descriptor() == -1,
                    "Helper loss did not revoke its descriptor and retain recovery responsibility");
                check(!client->ownedConfiguration() && client->ownedDevice().isEmpty(), "Lost helper retained active ownership facts");
                previous = results.size();
                client->restore();
                wait([&] { return results.size() == previous+1; });
                check(results.last().succeeded() && client->state() == Client::State::Idle, "Fresh Qt-authorized recovery failed");
            } else if (scenario == "destroy") {
                client.reset();
                QDeadlineTimer settle(200);
                while (!settle.hasExpired()) { QCoreApplication::processEvents(); QThread::msleep(1); }
            } else {
                previous = results.size();
                client->restore();
                wait([&] { return results.size() == previous+1; });
                check(results.last().succeeded() && client->state() == Client::State::Idle && client->descriptor() == -1,
                    "Restore reported completion before its descriptor and receipt were released");
                check(!client->ownedConfiguration() && client->ownedDevice().isEmpty(), "Restored helper retained active ownership facts");
            }
        }
    }
    std::cout << "PASS: Qt helper client " << scenario.toStdString() << '\n';
    return 0;
} catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
