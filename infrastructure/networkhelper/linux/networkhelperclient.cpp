#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "networkhelperpaths.h"
#include "infrastructure/process/linux/trustedexecutable.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QPointer>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QScopeGuard>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
constexpr int inspectionTimeoutMs = 3000;
constexpr int operationTimeoutMs = 4 * LinuxRouteOperationTimeoutMs + LinuxHelperPacketTimeoutMs;

QProcessEnvironment cleanEnvironment()
{
    auto environment = QProcessEnvironment::systemEnvironment();
    for (const auto &key : environment.keys())
        if (key.startsWith("QT") || key.startsWith("QML") || key.startsWith("LD_") || key.startsWith("DYLD_")) environment.remove(key);
    environment.insert("LC_ALL", "C.UTF-8");
    return environment;
}

// An application-owned watcher reaps even if its client disappears; it never kills a privileged worker.
class ChildWatcher final : public QObject
{
public:
    ChildWatcher(pid_t process, std::function<void(int)> callback) : QObject(QCoreApplication::instance()), pid(process), done(std::move(callback))
    {
        descriptor = int(::syscall(SYS_pidfd_open, pid, 0));
        if (descriptor >= 0) {
            auto *notifier = new QSocketNotifier(descriptor, QSocketNotifier::Read, this);
            connect(notifier, &QSocketNotifier::activated, this, [this] { reap(); });
        } else {
            // Older kernels/descriptor pressure still need child reaping, without a signal handler.
            auto *timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, [this] { reap(); });
            timer->start(1000);
        }
        QTimer::singleShot(0, this, [this] { reap(); });
    }
    ~ChildWatcher() override { if (descriptor >= 0) ::close(descriptor); }
private:
    void reap()
    {
        if (completed) return;
        int status = 0;
        pid_t result;
        do { result = ::waitpid(pid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
        if (!result) return;
        completed = true;
        done(result == pid ? status : -1);
        deleteLater();
    }
    pid_t pid;
    int descriptor = -1;
    bool completed = false;
    std::function<void(int)> done;
};
}

LinuxNetworkHelperClient::LinuxNetworkHelperClient(QObject *parent) : QObject(parent)
{
    deadline.setSingleShot(true);
    connect(&deadline, &QTimer::timeout, this, &LinuxNetworkHelperClient::timeout);
    connect(&probe, &QProcess::finished, this, &LinuxNetworkHelperClient::inspected);
    probe.setStandardErrorFile(QProcess::nullDevice());
    connect(&probe, &QProcess::readyReadStandardOutput, this, [this] {
        if (current == State::Inspecting && probe.bytesAvailable() > LinuxHelperPacketBytes) {
            outcome = Result{Status::Failed, "Network helper inspection exceeded its response budget."};
            probe.kill();
        }
    });
    connect(&probe, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart && current == State::Inspecting)
            finish(outcome.value_or(Result{Status::Failed, "Cannot inspect the installed network helper."}),
                retryState());
    });
}

LinuxNetworkHelperClient::~LinuxNetworkHelperClient() { closeChannels(); }

void LinuxNetworkHelperClient::setState(State value)
{
    current = value;
    emit stateChanged(value);
}

LinuxNetworkHelperClient::State LinuxNetworkHelperClient::retryState() const
{
    return operation == Operation::Recover ? State::RecoveryRequired
        : operation == Operation::Cleanup ? State::CleanupRequired : State::Idle;
}

void LinuxNetworkHelperClient::closeChannels()
{
    deadline.stop();
    delete listener; listener = nullptr;
    delete receiver; receiver = nullptr;
    for (int *fd : {&server, &control, &device}) { if (*fd >= 0) ::close(*fd); *fd = -1; }
}

void LinuxNetworkHelperClient::finish(Result result, State state)
{
    deadline.stop();
    if (state != State::Active) closeChannels();
    const auto completed = operation;
    QPointer<LinuxNetworkHelperClient> guard(this);
    setState(state);
    if (guard) emit finished(completed, result);
}

QJsonObject LinuxNetworkHelperClient::command(const char *name) const
{
    return {{"version", LinuxHelperProtocol}, {"owner", connection.toString(QUuid::WithoutBraces)}, {"operation", QString::fromLatin1(name)}};
}

void LinuxNetworkHelperClient::apply(const QUuid &owner, const LinuxHelperConfiguration &configuration)
{
    if (configuration.capturePrefixes.size() > LinuxRouteSnapshotRows || configuration.originalPrefixes.size() > LinuxRouteSnapshotRows
        || configuration.dnsDomains.size() > LinuxRouteSnapshotRows) {
        emit finished(Operation::Apply, {Status::Failed, "Too many network configuration entries."}); return;
    }
    const auto request = linuxHelperApplyRequest(owner, configuration);
    if (!parseLinuxHelperApply(owner, request)) {
        emit finished(Operation::Apply, {Status::Failed, "Invalid network helper configuration."}); return;
    }
    begin(owner, Operation::Apply, request);
}

void LinuxNetworkHelperClient::recover(const QUuid &owner)
{
    begin(owner, Operation::Recover, {{"version", LinuxHelperProtocol}, {"owner", owner.toString(QUuid::WithoutBraces)}, {"operation", "recover"}});
}

void LinuxNetworkHelperClient::extend(const QStringList &addresses)
{
    const auto request = linuxHelperExtendRequest(connection,addresses);
    const auto parsed = parseLinuxHelperExtend(connection,request);
    if (current != State::Active || device < 0 || !parsed) {
        emit finished(Operation::Extend,{Status::Failed,"DNS route publication requires active ownership and canonical addresses."});
        return;
    }
    changeRoutes(Operation::Extend, *parsed, request);
}

void LinuxNetworkHelperClient::reconcile(const QStringList &prefixes)
{
    const auto request = linuxHelperRoutesRequest(connection,prefixes);
    const auto parsed = parseLinuxHelperRoutes(connection,request);
    if (current != State::Active || device < 0 || !parsed) {
        emit finished(Operation::Routes,{Status::Failed,"Route changes require active ownership and canonical prefixes."});
        return;
    }
    changeRoutes(Operation::Routes, *parsed, request);
}

void LinuxNetworkHelperClient::changeRoutes(Operation action, const QStringList &targets, const QJsonObject &request)
{
    pendingExtension = targets;
    operation = action; outcome.reset();
    QPointer<LinuxNetworkHelperClient> guard(this);
    setState(State::Extending);
    if (!guard) return;
    if (current == State::CancellingExtend) { restoreActive(); return; }
    if (current != State::Extending) return;
    deadline.start(operationTimeoutMs);
    send(request);
}

void LinuxNetworkHelperClient::cleanupRestored(const QUuid &owner)
{
    begin(owner, Operation::Cleanup, {{"version", LinuxHelperProtocol}, {"owner", owner.toString(QUuid::WithoutBraces)}, {"operation", "cleanup"}});
}

void LinuxNetworkHelperClient::begin(const QUuid &owner, Operation action, QJsonObject request)
{
    if (child > 0 || (current != State::Idle && current != State::RecoveryRequired && current != State::CleanupRequired)) {
        emit finished(action, {Status::Failed, "A network helper operation is already active."}); return;
    }
    if (owner.isNull() || ::getuid() == 0 || ::getuid() != ::geteuid()) {
        emit finished(action, {Status::PermissionDenied, "The network host must run as the original unprivileged account."}); return;
    }
    if (current == State::RecoveryRequired && action != Operation::Recover) {
        emit finished(action, {Status::Failed, "Existing network ownership requires recovery.", true}); return;
    }
    if ((current == State::CleanupRequired && action != Operation::Cleanup)
        || ((current == State::RecoveryRequired || current == State::CleanupRequired) && owner != connection)) {
        emit finished(action, {Status::Failed, "Complete the existing connection's recovery before replacing it.", true}); return;
    }
    operation = action; connection = owner; initial = std::move(request); outcome.reset(); ++generation;
    if (!trustedLinuxExecutable(LinuxNetworkHelperPath, false) || !trustedLinuxExecutable(LinuxNetworkHelperAuthorizationPath, true)) {
        finish({Status::Unsupported, "A trusted system network helper and authorization program must be installed."},
            retryState()); return;
    }
    QPointer<LinuxNetworkHelperClient> guard(this);
    setState(State::Inspecting);
    if (!guard || current != State::Inspecting) return;
    probe.setProcessEnvironment(cleanEnvironment());
    probe.setStandardInputFile(QProcess::nullDevice());
    deadline.start(inspectionTimeoutMs);
    probe.start(QString::fromLatin1(LinuxNetworkHelperPath), {"--version"});
}

void LinuxNetworkHelperClient::inspected(int exitCode, QProcess::ExitStatus status)
{
    if (current != State::Inspecting) return;
    deadline.stop();
    if (outcome) { finish(*outcome, retryState()); return; }
    const auto bytes = probe.readAllStandardOutput();
    const auto facts = bytes.size() <= LinuxHelperPacketBytes ? QJsonDocument::fromJson(bytes).object() : QJsonObject{};
    if (status != QProcess::NormalExit || exitCode != 0 || facts.size() != 5 || facts["worker"] != "network-helper"
        || facts["protocol"] != LinuxHelperProtocol || !facts["qt"].toString().startsWith("6.")
        || !QRegularExpression("^[0-9a-f]{40}$").match(facts["revision"].toString()).hasMatch()
        || (facts["source_state"] != "clean" && facts["source_state"] != "archive")) {
        finish({Status::Unsupported, "The installed network helper must be updated or repaired."},
            retryState()); return;
    }
    authorize();
}

void LinuxNetworkHelperClient::authorize()
{
    server = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    const auto name = linuxHelperSocketName(::getuid(), connection);
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    if (server < 0 || size_t(name.size()) >= sizeof(address.sun_path)) { failed("Cannot create a private helper listener."); return; }
    std::memcpy(address.sun_path + 1, name.constData(), size_t(name.size()));
    if (::bind(server, reinterpret_cast<sockaddr *>(&address), socklen_t(offsetof(sockaddr_un, sun_path) + 1 + name.size())) != 0
        || ::listen(server, 4) != 0) { failed("Cannot bind the owned helper listener."); return; }

    const auto environment = cleanEnvironment().toStringList();
    QList<QByteArray> strings{QByteArray(LinuxNetworkHelperAuthorizationPath), "--disable-internal-agent", QByteArray(LinuxNetworkHelperPath),
        connection.toByteArray(QUuid::WithoutBraces), QByteArray::number(::getpid())};
    QList<QByteArray> variables;
    for (const auto &item : environment) variables.append(item.toUtf8());
    QList<char *> arguments, env;
    for (auto &item : strings) arguments.append(item.data());
    arguments.append(nullptr);
    for (auto &item : variables) env.append(item.data());
    env.append(nullptr);
    posix_spawn_file_actions_t files;
    posix_spawnattr_t attributes;
    if (::posix_spawn_file_actions_init(&files) != 0) { failed("Cannot prepare authorization process descriptors."); return; }
    const auto closeFiles = qScopeGuard([&] { ::posix_spawn_file_actions_destroy(&files); });
    if (::posix_spawnattr_init(&attributes) != 0) { failed("Cannot prepare authorization process attributes."); return; }
    const auto closeAttributes = qScopeGuard([&] { ::posix_spawnattr_destroy(&attributes); });
    if (::posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDONLY, 0) != 0
        || ::posix_spawn_file_actions_addopen(&files, 1, "/dev/null", O_WRONLY, 0) != 0
        || ::posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) != 0
        || ::posix_spawn_file_actions_addclosefrom_np(&files, 3) != 0
        || ::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP) != 0 || ::posix_spawnattr_setpgroup(&attributes, 0) != 0
        || ::posix_spawn(&child, LinuxNetworkHelperAuthorizationPath, &files, &attributes, arguments.data(), env.data()) != 0) {
        child = -1; failed("Cannot start system authorization."); return;
    }
    const auto serial = generation;
    const auto pid = child;
    QPointer<LinuxNetworkHelperClient> guard(this);
    new ChildWatcher(pid, [guard, serial, pid](int status) { if (guard) guard->exited(serial, pid, status); });
    listener = new QSocketNotifier(server, QSocketNotifier::Read, this);
    connect(listener, &QSocketNotifier::activated, this, &LinuxNetworkHelperClient::accept);
    setState(State::Authorizing);
}

bool LinuxNetworkHelperClient::send(const QJsonObject &packet)
{
    const auto result = sendLinuxHelperPacket(control, packet, -1, 0);
    if (result.succeeded()) return true;
    failed(result.detail); return false;
}

void LinuxNetworkHelperClient::accept()
{
    const int accepted = ::accept4(server, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (accepted < 0) return;
    ucred peer{}; socklen_t size = sizeof(peer);
    if (current != State::Authorizing || ::getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0
        || size != sizeof(peer) || peer.uid != 0 || peer.pid != child) { ::close(accepted); return; }
    control = accepted;
    delete listener; listener = nullptr;
    ::close(server); server = -1;
    receiver = new QSocketNotifier(control, QSocketNotifier::Read, this);
    connect(receiver, &QSocketNotifier::activated, this, &LinuxNetworkHelperClient::receive);
    QPointer<LinuxNetworkHelperClient> guard(this);
    setState(operation == Operation::Apply ? State::Applying : State::Restoring);
    if (!guard || (current != State::Applying && current != State::CancellingApply && current != State::Restoring)) return;
    deadline.start(operationTimeoutMs);
    const auto submitted = sendLinuxHelperPacket(control, initial, -1, 0);
    if (!submitted.succeeded()) finish(outcome.value_or(submitted), retryState());
}

void LinuxNetworkHelperClient::receive()
{
    if (control < 0) return;
    QJsonObject packet; int received = -1;
    const auto result = receiveLinuxHelperPacket(control, packet, received, 0);
    const auto close = qScopeGuard([&] { if (received >= 0) ::close(received); });
    const auto code = packet["status"].toInteger(-1);
    if (!result.succeeded() || packet.size() != 7 || packet["version"] != LinuxHelperProtocol
        || packet["owner"] != connection.toString(QUuid::WithoutBraces) || code < 0 || code > int(Status::TimedOut)
        || !packet["detail"].isString() || !packet["changed"].isBool() || !packet["device"].isObject()) {
        failed("Invalid network helper response or premature channel closure."); return;
    }
    Result returned{Status(code), packet["detail"].toString(), packet["changed"].toBool()};
    const auto phase = packet["state"].toString();
    if (phase == "active" && returned.succeeded() && (current == State::Applying || current == State::CancellingApply)) {
        if (child < 0) { failed("The helper exited before device handoff completed."); return; }
        const auto info = packet["device"].toObject();
        ifreq native{};
        const auto expected = linuxTunName(connection);
        if (received < 0 || info.size() != 4 || info["owner"] != connection.toString(QUuid::WithoutBraces)
            || info["interface"] != QString::fromLatin1(expected) || info["index"].toInteger(-1) != ::if_nametoindex(expected.constData())
            || !info["configuration"].isObject() || info["configuration"].toObject()["applied"].toObject()["ipv6_disabled"] != true
            || ::ioctl(received, TUNGETIFF, &native) != 0
            || QByteArray(native.ifr_name) != expected
            || (native.ifr_flags & (IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE | IFF_PERSIST)) != (IFF_TUN | IFF_NO_PI)
            || !(::fcntl(received, F_GETFD) & FD_CLOEXEC)) { failed("The helper did not hand over its owned raw IP device."); return; }
        if (current == State::CancellingApply) {
            restoreActive();
            return;
        }
        const int flags = ::fcntl(received, F_GETFL);
        if (flags < 0 || ::fcntl(received, F_SETFL, flags | O_NONBLOCK) != 0) {
            failed("Cannot prepare interruptible packet I/O for the owned device."); return;
        }
        configuration = parseLinuxHelperApply(connection, initial);
        if (!configuration) { failed("The active device lost its confirmed configuration."); return; }
        deviceInfo = info;
        initial = {};
        device = received; received = -1;
        finish(returned, State::Active); return;
    }
    if (received >= 0 || !packet["device"].toObject().isEmpty()) { failed("Unexpected descriptor in a helper response."); return; }
    if (phase == "active" && returned.succeeded() && (current == State::Extending || current == State::CancellingExtend)) {
        if (child < 0) { failed("The helper exited before DNS route publication completed."); return; }
        if (current == State::CancellingExtend) restoreActive();
        else {
            if (!configuration) { failed("The active device lost its confirmed configuration."); return; }
            if (operation == Operation::Routes) {
                configuration->capturePrefixes = pendingExtension;
                configuration->originalPrefixes.append(pendingExtension);
                configuration->originalPrefixes.removeDuplicates();
            } else {
                for (auto *prefixes : {&configuration->capturePrefixes, &configuration->originalPrefixes}) {
                    for (const auto &address : pendingExtension) {
                        bool covered = false;
                        for (const auto &prefix : *prefixes) covered |= ipv4PrefixContainsAddress(prefix, address);
                        if (!covered) prefixes->append(address + "/32");
                    }
                }
            }
            pendingExtension.clear();
            finish(returned,State::Active);
        }
        return;
    }
    if ((operation == Operation::Cleanup || operation == Operation::Recover) && current == State::Restoring
        && phase == "cleaned" && returned.succeeded()) {
        outcome = returned;
    } else if ((current == State::Applying || current == State::CancellingApply || current == State::Extending
                || current == State::CancellingExtend || current == State::Restoring) && phase == "restored") {
        if (!returned.succeeded() && current == State::Restoring) { returned.mayHaveChanged = true; finish(returned, State::RecoveryRequired); return; }
        if (!outcome) outcome = returned;
        current = State::Acknowledging;
        if (!send(command("acknowledge"))) return;
    } else {
        if (!returned.succeeded() && (phase == "prepared" || phase == "active")) {
            returned.mayHaveChanged = true;
            finish(returned, operation == Operation::Cleanup ? State::CleanupRequired : State::RecoveryRequired);
        } else failed(returned.detail.isEmpty() ? "Network ownership could not be restored." : returned.detail);
        return;
    }
    if (device >= 0) { ::close(device); device = -1; }
    receiver->setEnabled(false);
    deadline.start(LinuxHelperPacketTimeoutMs);
    setState(State::Acknowledging);
}

void LinuxNetworkHelperClient::restore()
{
    if (current == State::RecoveryRequired) { recover(connection); return; }
    if (current == State::CleanupRequired) { cleanupRestored(connection); return; }
    if (current == State::Idle) { emit finished(Operation::Restore, {}); return; }
    if (current != State::Active) { cancel(); return; }
    operation = Operation::Restore; outcome.reset();
    restoreActive();
}

void LinuxNetworkHelperClient::restoreActive()
{
    if (device >= 0) { ::close(device); device = -1; }
    QPointer<LinuxNetworkHelperClient> guard(this);
    setState(State::Restoring);
    if (!guard || current != State::Restoring) return;
    deadline.start(operationTimeoutMs);
    send(command("restore"));
}

void LinuxNetworkHelperClient::cancel()
{
    if (current == State::Active) { restore(); return; }
    if (current == State::Inspecting) {
        outcome = Result{Status::Cancelled, "Network authorization was cancelled."};
        probe.kill(); return; // Only this ordinary-user inspection process is terminated.
    }
    if (current == State::Authorizing) {
        closeChannels();
        // No operation packet has been sent, so even a just-authorized child has no network writes to abandon.
        if (child > 0) ::kill(child, SIGTERM);
        outcome = Result{Status::Cancelled, "Network authorization was cancelled."};
        setState(State::CancellingAuthorization); return;
    }
    if (current == State::Applying) {
        outcome = Result{Status::Cancelled, "Network configuration was cancelled.", true};
        setState(State::CancellingApply);
    }
    if (current == State::Extending) {
        outcome = Result{Status::Cancelled,"DNS route publication was cancelled.",true};
        setState(State::CancellingExtend);
    }
}

void LinuxNetworkHelperClient::timeout()
{
    if (current == State::Inspecting) { outcome = Result{Status::TimedOut, "Network helper inspection timed out."}; probe.kill(); return; }
    finish({Status::TimedOut, "Network helper response timed out.", true},
        current == State::Acknowledging || operation == Operation::Cleanup ? State::CleanupRequired : State::RecoveryRequired);
}

void LinuxNetworkHelperClient::failed(const QString &detail)
{
    if (current == State::Active) {
        closeChannels();
        QPointer<LinuxNetworkHelperClient> guard(this);
        setState(State::RecoveryRequired);
        if (guard) emit ownershipLost({Status::Failed, detail, true});
        return;
    }
    const bool unknown = current == State::Applying || current == State::Restoring || current == State::CancellingApply
        || current == State::Extending || current == State::CancellingExtend
        || current == State::Acknowledging || operation == Operation::Recover;
    finish({Status::Failed, detail, unknown}, operation == Operation::Cleanup || current == State::Acknowledging
        ? State::CleanupRequired : unknown ? State::RecoveryRequired : State::Idle);
}

void LinuxNetworkHelperClient::exited(quint64 serial, pid_t process, int status)
{
    if (serial != generation || process != child) return;
    child = -1;
    if (current == State::RecoveryRequired || current == State::CleanupRequired) {
        if (current == State::CleanupRequired && status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) setState(State::Idle);
        return;
    }
    if (current == State::Acknowledging) {
        if (status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) finish(outcome.value_or(Result{}), State::Idle);
        else finish({Status::Failed, "Network restoration is confirmed, but its receipt needs cleanup."}, State::CleanupRequired);
        return;
    }
    if (current == State::Authorizing || current == State::CancellingAuthorization) {
        const auto code = status >= 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        const auto returned = outcome.value_or(Result{code == 126 ? Status::Cancelled : code == 127 ? Status::PermissionDenied : Status::Failed,
            code == 126 ? "System authorization was cancelled." : code == 127 ? "System authorization was denied or unavailable." : "The authorization process ended before connection."});
        finish(returned, retryState()); return;
    }
    // A final packet may already be queued when the child becomes waitable.
    if (control >= 0 && current != State::Active) {
        pollfd item{control, POLLIN, 0};
        if (::poll(&item, 1, 0) > 0 && (item.revents & POLLIN)) {
            QPointer<LinuxNetworkHelperClient> guard(this);
            receive();
            if (!guard) return;
            if (current == State::Acknowledging && status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) { finish(outcome.value_or(Result{}), State::Idle); return; }
        }
    }
    if (current != State::Idle && current != State::RecoveryRequired && current != State::CleanupRequired)
        failed("The privileged network helper exited unexpectedly.");
}
