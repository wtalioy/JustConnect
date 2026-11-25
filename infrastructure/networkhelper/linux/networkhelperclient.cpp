#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "infrastructure/networkhelper/linux/networkhelperavailability.h"
#include <QJsonDocument>
#include <QRandomGenerator>
#include <QSocketNotifier>
#include <QStandardPaths>
#include <qendian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace {
QByteArray abstractSocketName()
{
    // Private per-launch abstract namespace address; only the pkexec-authorized
    // helper learns it, and both sides verify SO_PEERCRED.
    const auto random = QRandomGenerator::system()->generate64();
    return QStringLiteral("justconnect-helper-%1").arg(random, 16, 16, QChar('0')).toUtf8();
}

bool closeFd(int &fd)
{
    if (fd < 0) return false;
    ::close(fd);
    fd = -1;
    return true;
}

bool writeAll(int fd, const QByteArray &frame)
{
    qint64 offset = 0;
    while (offset < frame.size()) {
        const auto written = ::send(fd, frame.constData() + offset, size_t(frame.size() - offset), MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        offset += written;
    }
    return true;
}
}

LinuxNetworkHelperClient::LinuxNetworkHelperClient(QObject *parent, Launcher launcher_, int authorizedUid_)
    : QObject(parent), launcher(std::move(launcher_)), authorizedUid(authorizedUid_)
{
    connect(&process, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus status) {
        helperAlive = false;
        const auto detail = QString::fromUtf8(process.readAllStandardError().trimmed());
        if (state_ == State::Authorizing && listenerFd >= 0) {
            // The helper never dialed back: pkexec could not run it.
            const bool denied = status == QProcess::ExitStatus::NormalExit
                && (exitCode == 126 || exitCode == 127);
            fail(Operation::Inspect,
                denied ? QStringLiteral("Automatic routing was not authorized: %1.").arg(detail.isEmpty()
                        ? QStringLiteral("the authorization dialog was dismissed")
                        : detail)
                    : QStringLiteral("Cannot start the privileged network helper: %1.").arg(detail.isEmpty()
                        ? QString::number(exitCode) : detail),
                denied ? PlatformOperationResult::Status::PermissionDenied : PlatformOperationResult::Status::Failed);
        } else if (state_ != State::Idle || connectionFd >= 0) {
            channelClosed(QStringLiteral("The privileged network helper exited unexpectedly."));
        }
    });
    connect(&process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (state_ == State::Authorizing && listenerFd >= 0)
            fail(Operation::Inspect, QStringLiteral("Cannot launch pkexec (code %1).").arg(int(error)));
    });
    deadline.setSingleShot(true);
    connect(&deadline, &QTimer::timeout, this, [this] {
        const bool authorizing = state_ == State::Authorizing;
        const QString detail = authorizing ? QStringLiteral("The authorization dialog timed out.")
            : QStringLiteral("The network helper did not answer in time; its session is withdrawn.");
        const auto status = authorizing ? PlatformOperationResult::Status::Cancelled
            : PlatformOperationResult::Status::TimedOut;
        // Closing the channel makes the helper restore everything it owns.
        channelClosed(detail, status);
    });
}

LinuxNetworkHelperClient::~LinuxNetworkHelperClient()
{
    connectionNotifier.reset();
    // EOF makes the helper withdraw everything it owns and exit; kill only
    // if it fails to leave within the grace period.
    closeFd(connectionFd);
    listenerNotifier.reset();
    closeFd(listenerFd);
    if (process.state() == QProcess::Running) {
        process.waitForFinished(3000);
        if (process.state() == QProcess::Running) process.kill();
        process.waitForFinished(1000);
    }
}

LinuxNetworkHelperClient::State LinuxNetworkHelperClient::state() const { return state_; }
qint64 LinuxNetworkHelperClient::helperPID() const { return process.state() == QProcess::Running ? process.processId() : 0; }

void LinuxNetworkHelperClient::setState(State state)
{
    if (state_ == state) return;
    state_ = state;
    emit stateChanged(state);
}

void LinuxNetworkHelperClient::fail(Operation operation, const QString &detail,
    PlatformOperationResult::Status status)
{
    deadline.stop();
    closeFd(connectionFd);
    connectionNotifier.reset();
    closeFd(listenerFd);
    listenerNotifier.reset();
    closeFd(descriptor_);
    helperAlive = false;
    buffer.clear();
    expected = 0;
    ownedDevice_.reset();
    ownedConfiguration_.reset();
    dnsMode_.clear();
    setState(State::Idle);
    currentOperation = Operation::Inspect;
    pendingPacket = {};
    emit finished(operation, {status, detail, true});
}

void LinuxNetworkHelperClient::inspect(const QUuid &id)
{
    if (state_ != State::Idle || id.isNull()) {
        emit finished(Operation::Inspect, {PlatformOperationResult::Status::Failed,
            QStringLiteral("Previous helper interaction is incomplete."), true});
        return;
    }
    if (!helperAlive && process.state() != QProcess::NotRunning) {
        emit finished(Operation::Inspect, {PlatformOperationResult::Status::Failed,
            QStringLiteral("The previous network helper is still exiting. Retry recovery."), restorationPending_});
        return;
    }
    attempt_ = id;
    if (helperAlive && connectionFd >= 0) {
        // The authorized helper from a previous session still runs; probe it
        // instead of prompting for authorization again.
        owner_ = id;
        request_ = QUuid::createUuid();
        currentOperation = Operation::Inspect;
        setState(State::Inspecting);
        deadline.start(LinuxHelperOperationTimeoutMs);
        if (!send(linuxHelperRequest("probe", id, request_)))
            fail(Operation::Inspect, QStringLiteral("Cannot talk to the network helper."));
        return;
    }
    start(id);
    setState(State::Authorizing);
    deadline.start(LinuxHelperAuthorizationTimeoutMs);
    launchHelper();
}

void LinuxNetworkHelperClient::start(const QUuid &id)
{
    attempt_ = id;
    owner_ = {};
    request_ = {};
    closeRequested = false;
    helperAlive = false;
    dnsMode_.clear();
    closeFd(descriptor_);
    ownedDevice_.reset();
    ownedConfiguration_.reset();
    buffer.clear();
    expected = 0;
    closeFd(connectionFd);
    connectionNotifier.reset();
    closeFd(listenerFd);
    listenerNotifier.reset();

    listenerFd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listenerFd < 0) return;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    socketName = abstractSocketName();
    // Abstract namespace: leading NUL, then the name; the address length
    // carries the name, so no terminator is added. The name travels as raw
    // bytes, so the member must stay a QByteArray: a QString would memcpy its
    // UTF-16 representation and bind a name the helper can never dial.
    std::memcpy(address.sun_path + 1, socketName.constData(), size_t(socketName.size()));
    const socklen_t length = socklen_t(offsetof(sockaddr_un, sun_path) + 1 + socketName.size());
    if (::bind(listenerFd, reinterpret_cast<const sockaddr *>(&address), length) != 0
        || ::listen(listenerFd, 1) != 0) {
        closeFd(listenerFd);
        return;
    }
    listenerNotifier = std::make_unique<QSocketNotifier>(listenerFd, QSocketNotifier::Read);
    connect(listenerNotifier.get(), &QSocketNotifier::activated, this, [this] { listenCompleted(); });
}

void LinuxNetworkHelperClient::launchHelper()
{
    const auto socketArgument = QStringLiteral("@") + QString::fromUtf8(socketName);
    if (launcher) {
        launcher(&process, {QStringLiteral("justconnect-network-helper"),
            QStringLiteral("--connect"), socketArgument,
            QString::number(::getpid()), QString::number(::getuid())});
        return;
    }
    const auto program = linuxNetworkHelperExecutable();
    if (program.isEmpty()) {
        fail(Operation::Inspect, QStringLiteral("The network helper executable is unavailable."));
        return;
    }
    process.setProgram(QStringLiteral("pkexec"));
    process.setArguments({program, QStringLiteral("--connect"), socketArgument,
        QString::number(::getpid()), QString::number(::getuid())});
    process.start();
}

void LinuxNetworkHelperClient::listenCompleted()
{
    if (listenerFd < 0) return;
    connectionFd = ::accept4(listenerFd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (connectionFd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
        closeFd(listenerFd);
        listenerNotifier.reset();
        fail(Operation::Inspect, QStringLiteral("The network helper connection failed."));
        return;
    }
    // Only the elevated helper may dial back.
    ucred credentials{};
    socklen_t size = sizeof(credentials);
    if (::getsockopt(connectionFd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 || credentials.uid != authorizedUid) {
        channelClosed(QStringLiteral("An unexpected process answered the helper socket."));
        return;
    }
    closeFd(listenerFd);
    listenerNotifier.reset();
    if (state_ != State::Authorizing) return; // Authorization already failed; the socket tears down.
    deadline.stop();
    setState(State::Inspecting);
    connectionNotifier = std::make_unique<QSocketNotifier>(connectionFd, QSocketNotifier::Read);
    connect(connectionNotifier.get(), &QSocketNotifier::activated, this, [this] { connectionReady(); });
    helperAlive = true;
    owner_ = attempt_;
    request_ = QUuid::createUuid();
    currentOperation = Operation::Inspect;
    pendingPacket = linuxHelperRequest("probe", attempt_, request_);
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(pendingPacket))
        fail(Operation::Inspect, QStringLiteral("Cannot talk to the network helper."));
}

void LinuxNetworkHelperClient::connectionReady()
{
    while (connectionFd >= 0 && connectionNotifier && readFrame()) {
        // Drain everything the helper sent in this activation.
    }
}

bool LinuxNetworkHelperClient::readFrame()
{
    char control[CMSG_SPACE(sizeof(int))];
    for (;;) {
        // expected==0: collecting the 4-byte length header; otherwise the
        // whole frame (header + body) is reassembled into buffer.
        const qint64 need = expected == 0 ? 4 : expected;
        const qint64 have = buffer.size();
        if (have >= need) {
            if (expected == 0) {
                const auto length = qFromBigEndian<quint32>(buffer.constData());
                if (length == 0 || length > quint32(LinuxHelperRequestBytes)) {
                    channelClosed(QStringLiteral("The network helper sent an out-of-bound frame."));
                    return false;
                }
                // Keep the received header bytes and let the receive block below
                // grow the buffer for the body; resizing to the full frame here
                // would make the next pass believe the body already arrived.
                expected = 4 + qint64(length);
                continue;
            }
            const QJsonDocument document = QJsonDocument::fromJson(buffer.mid(4));
            buffer.clear();
            expected = 0;
            if (!document.isObject()) {
                channelClosed(QStringLiteral("The network helper sent an unreadable reply."));
                return false;
            }
            handleReply(document.object());
            return true;
        }
        buffer.resize(int(need));
        iovec vector{};
        vector.iov_base = buffer.data() + have;
        vector.iov_len = size_t(need - have);
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        const auto received = ::recvmsg(connectionFd, &message, MSG_CMSG_CLOEXEC);
        if (received == 0) {
            channelClosed({});
            return false;
        }
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                buffer.resize(int(have));
                return false; // Wait for the notifier.
            }
            if (errno == EINTR) continue;
            channelClosed({});
            return false;
        }
        if (message.msg_flags & MSG_CTRUNC) {
            channelClosed(QStringLiteral("The network helper reply lost its descriptor."));
            return false;
        }
        for (auto header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
                && header->cmsg_len >= CMSG_LEN(sizeof(int))) {
                int passed = -1;
                std::memcpy(&passed, CMSG_DATA(header), sizeof(int));
                if (descriptor_ >= 0) ::close(descriptor_);
                descriptor_ = passed;
            }
        }
        if (received < need - have) buffer.resize(int(have + received));
    }
}

void LinuxNetworkHelperClient::handleReply(const QJsonObject &packet)
{
    const auto requestPacket = pendingPacket;
    pendingPacket = {};
    const auto operation = currentOperation;
    currentOperation = Operation::Inspect;
    deadline.stop();
    const auto result = parseLinuxHelperResponse(packet, requestPacket);
    if (!result) {
        // The protocol lost sync with the helper's session state; tear the
        // channel down so its EOF path restores everything it owns.
        const auto detail = QStringLiteral("The network helper reply is malformed.");
        const bool owned = state_ == State::Active || state_ == State::Extending || state_ == State::Reconciling;
        channelClosed(detail);
        if (owned) emit finished(operation, {PlatformOperationResult::Status::Failed, detail, true});
        return;
    }
    switch (state_) {
    case State::Inspecting:
        dnsMode_ = parseLinuxHelperDnsMode(packet);
        if (result->succeeded()) restorationPending_ = false;
        setState(State::Idle);
        emit finished(operation, *result);
        return;
    case State::Applying:
        if (result->succeeded()) {
            const auto device = parseLinuxHelperDevice(packet);
            if (!device) {
                // The helper configured the device but our envelope is wrong;
                // tearing the channel down rolls the session back.
                channelClosed(QStringLiteral("The network helper device envelope is invalid."));
                return;
            }
            ownedDevice_ = *device;
            ownedConfiguration_ = appliedConfiguration;
            dnsMode_ = parseLinuxHelperDnsMode(packet);
            setState(State::Active);
        } else {
            // The helper rolled its partial session back; keep the channel so
            // a retry skips the polkit prompt.
            closeFd(descriptor_);
            setState(State::Idle);
        }
        emit finished(operation, *result);
        return;
    case State::Extending:
    case State::Reconciling:
        setState(State::Active);
        emit finished(operation, *result);
        return;
    case State::Restoring:
        ownedDevice_.reset();
        ownedConfiguration_.reset();
        closeFd(descriptor_);
        // A failed restore retains the helper's ownership record: the capture
        // stays attached and only a retried restore over the same channel can
        // withdraw it. Returning to the active state keeps that retry possible;
        // dropping to Idle here would leave every later apply answered with
        // "a capture is already active" until the helper process restarts.
        if (result->succeeded()) restorationPending_ = false;
        setState(result->succeeded() ? State::Idle : State::Active);
        emit finished(operation, *result);
        return;
    case State::Idle:
        if (operation == Operation::Close) emit finished(operation, *result);
        return;
    default:
        return;
    }
}

void LinuxNetworkHelperClient::channelClosed(const QString &detail,
    PlatformOperationResult::Status status)
{
    deadline.stop();
    const bool owned = state_ == State::Active || state_ == State::Extending
        || state_ == State::Reconciling;
    const bool restoring = state_ == State::Restoring;
    const bool pending = state_ == State::Authorizing || state_ == State::Inspecting
        || state_ == State::Applying;
    const auto operation = currentOperation;
    closeFd(connectionFd);
    connectionNotifier.reset();
    closeFd(listenerFd);
    listenerNotifier.reset();
    closeFd(descriptor_);
    helperAlive = false;
    closeRequested = false;
    buffer.clear();
    expected = 0;
    ownedDevice_.reset();
    ownedConfiguration_.reset();
    dnsMode_.clear();
    setState(State::Idle);
    currentOperation = Operation::Inspect;
    pendingPacket = {};
    const auto failure = [detail, status] {
        return PlatformOperationResult{status, detail.isEmpty()
            ? QStringLiteral("The network helper connection closed.") : detail, true};
    };
    if (owned) emit ownershipLost(failure());
    else if (restoring) emit finished(Operation::Restore, failure());
    else if (pending) emit finished(operation, failure());
    else if (process.state() == QProcess::Running && !closeRequested) process.kill();
}

bool LinuxNetworkHelperClient::send(const QJsonObject &packet)
{
    const auto compact = QJsonDocument(packet).toJson(QJsonDocument::Compact);
    if (compact.size() > LinuxHelperRequestBytes) return false;
    QByteArray frame(4 + compact.size(), Qt::Uninitialized);
    qToBigEndian<quint32>(quint32(compact.size()), frame.data());
    std::memcpy(frame.data() + 4, compact.constData(), size_t(compact.size()));
    if (!writeAll(connectionFd, frame)) return false;
    pendingPacket = packet;
    return true;
}

void LinuxNetworkHelperClient::apply(const QUuid &id, const LinuxHelperConfiguration &configuration)
{
    if (state_ != State::Idle || connectionFd < 0) {
        emit finished(Operation::Apply, {PlatformOperationResult::Status::Failed,
            QStringLiteral("Previous helper interaction is incomplete."), true});
        return;
    }
    appliedConfiguration = configuration;
    restorationPending_ = true;
    owner_ = id;
    request_ = QUuid::createUuid();
    currentOperation = Operation::Apply;
    setState(State::Applying);
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(linuxHelperApplyRequest(id, request_, configuration)))
        fail(Operation::Apply, QStringLiteral("Cannot talk to the network helper."));
}

void LinuxNetworkHelperClient::extend(const QStringList &addresses)
{
    if (state_ != State::Active || connectionFd < 0) {
        emit finished(Operation::Extend, {PlatformOperationResult::Status::Failed,
            QStringLiteral("No active network capture to extend."), true});
        return;
    }
    request_ = QUuid::createUuid();
    currentOperation = Operation::Extend;
    setState(State::Extending);
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(linuxHelperExtendRequest(owner_, request_, addresses)))
        fail(Operation::Extend, QStringLiteral("Cannot talk to the network helper."));
}

void LinuxNetworkHelperClient::reconcile(const QStringList &prefixes)
{
    if (state_ != State::Active || connectionFd < 0) {
        emit finished(Operation::Routes, {PlatformOperationResult::Status::Failed,
            QStringLiteral("No active network capture to reconcile."), true});
        return;
    }
    request_ = QUuid::createUuid();
    currentOperation = Operation::Routes;
    setState(State::Reconciling);
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(linuxHelperRoutesRequest(owner_, request_, prefixes)))
        fail(Operation::Routes, QStringLiteral("Cannot talk to the network helper."));
}

void LinuxNetworkHelperClient::restore()
{
    if (state_ != State::Active || connectionFd < 0) {
        emit finished(Operation::Restore, {PlatformOperationResult::Status::Failed,
            QStringLiteral("No active network capture to restore."), true});
        return;
    }
    request_ = QUuid::createUuid();
    currentOperation = Operation::Restore;
    setState(State::Restoring);
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(linuxHelperRequest("restore", owner_, request_)))
        fail(Operation::Restore, QStringLiteral("Cannot talk to the network helper."));
}

void LinuxNetworkHelperClient::close()
{
    if (state_ != State::Idle || connectionFd < 0 || !helperAlive || closeRequested) return;
    request_ = QUuid::createUuid();
    currentOperation = Operation::Close;
    closeRequested = true;
    deadline.start(LinuxHelperOperationTimeoutMs);
    if (!send(linuxHelperRequest("close", attempt_, request_)))
        channelClosed({});
}

void LinuxNetworkHelperClient::cancel()
{
    if (state_ == State::Idle || state_ == State::Active) return;
    channelClosed(QStringLiteral("The operation was cancelled."), PlatformOperationResult::Status::Cancelled);
}
