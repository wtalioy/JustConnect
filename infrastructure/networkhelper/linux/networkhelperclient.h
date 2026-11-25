#pragma once
#include "infrastructure/networkhelper/linux/networkhelperprotocol.h"
#include <QElapsedTimer>
#include <QObject>
#include <QProcess>
#include <QSocketNotifier>
#include <QTimer>
#include <functional>
#include <memory>
#include <optional>

// Unprivileged consumer of the privileged Linux network helper. One helper
// process per application launch: inspect() asks polkit (pkexec) to start the
// helper, which dials back to a private abstract unix socket this client
// listens on. Both sides verify SO_PEERCRED. The apply reply carries the TUN
// descriptor via SCM_RIGHTS; the helper keeps address/route/DNS ownership and
// withdraws everything on socket EOF, close, or a signal.
class LinuxNetworkHelperClient final : public QObject
{
    Q_OBJECT
public:
    enum class State { Idle, Authorizing, Inspecting, Applying, Active, Extending, Reconciling, Restoring };
    Q_ENUM(State)
    enum class Operation { Inspect, Apply, Extend, Routes, Restore, Close };
    Q_ENUM(Operation)
    // Test seam: replaces the pkexec launch; the launcher must start the process.
    using Launcher = std::function<void(QProcess *, const QStringList &)>;
    // authorizedUid is the socket peer the client accepts: root in production,
    // the test user when a stand-in helper exercises the protocol.
    explicit LinuxNetworkHelperClient(QObject *parent = nullptr, Launcher launcher = {}, int authorizedUid = 0);
    ~LinuxNetworkHelperClient() override;

    void inspect(const QUuid &attempt);
    void apply(const QUuid &owner, const LinuxHelperConfiguration &configuration);
    void extend(const QStringList &addresses);
    void reconcile(const QStringList &prefixes);
    void restore();
    void close();
    // Aborts any pending operation with a Cancelled result.
    void cancel();

    State state() const;
    bool restorationPending() const { return restorationPending_; }
    qint32 descriptor() const { return descriptor_; }
    std::optional<LinuxHelperDevice> ownedDevice() const { return ownedDevice_; }
    std::optional<LinuxHelperConfiguration> ownedConfiguration() const { return ownedConfiguration_; }
    // DNS mechanism the helper reported for the owned session.
    QString dnsMode() const { return dnsMode_; }
    QUuid owner() const { return owner_; }
    qint64 helperPID() const;

signals:
    void stateChanged(LinuxNetworkHelperClient::State state);
    void finished(LinuxNetworkHelperClient::Operation operation, const PlatformOperationResult &result);
    // The helper died or the channel broke while it owned network state.
    void ownershipLost(const PlatformOperationResult &result);

private:
    void setState(State state);
    void start(const QUuid &attempt);
    void launchHelper();
    void listenCompleted();
    void connectionReady();
    bool readFrame();
    void handleReply(const QJsonObject &packet);
    // Tears the channel down; emits ownershipLost for owned states and a
    // finished result for pending ones. Safe to call repeatedly.
    void channelClosed(const QString &detail = {},
        PlatformOperationResult::Status status = PlatformOperationResult::Status::Failed);
    void fail(Operation operation, const QString &detail,
        PlatformOperationResult::Status status = PlatformOperationResult::Status::Failed);
    bool send(const QJsonObject &packet);

    Launcher launcher;
    const int authorizedUid;
    int listenerFd = -1;
    int connectionFd = -1;
    std::unique_ptr<QSocketNotifier> listenerNotifier;
    std::unique_ptr<QSocketNotifier> connectionNotifier;
    QProcess process;
    QTimer deadline;
    QByteArray socketName;
    QUuid attempt_, owner_, request_;
    State state_ = State::Idle;
    Operation currentOperation = Operation::Inspect;
    bool helperAlive = false;
    bool closeRequested = false;
    bool restorationPending_ = false;
    // Frame reassembly: expected==0 collects the 4-byte big-endian length
    // header, then the whole frame into buffer.
    QByteArray buffer;
    qint64 expected = 0;
    QJsonObject pendingPacket;
    LinuxHelperConfiguration appliedConfiguration;
    QString dnsMode_;
    qint32 descriptor_ = -1;
    std::optional<LinuxHelperDevice> ownedDevice_;
    std::optional<LinuxHelperConfiguration> ownedConfiguration_;
};
