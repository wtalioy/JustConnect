#pragma once

#include "networkhelper.h"
#include <QObject>
#include <QProcess>
#include <QSocketNotifier>
#include <QTimer>

class LinuxNetworkHelperClient final : public QObject
{
    Q_OBJECT
public:
    enum class State { Idle, Inspecting, Authorizing, Applying, Active, Extending, Restoring, Acknowledging,
                       CancellingAuthorization, CancellingApply, CancellingExtend, RecoveryRequired, CleanupRequired };
    Q_ENUM(State)
    enum class Operation { Apply, Extend, Restore, Recover, Cleanup };
    Q_ENUM(Operation)
    explicit LinuxNetworkHelperClient(QObject *parent = nullptr);
    ~LinuxNetworkHelperClient() override;
    void apply(const QUuid &owner, const LinuxHelperConfiguration &configuration);
    void extend(const QStringList &addresses);
    void recover(const QUuid &owner);
    void cleanupRestored(const QUuid &owner);
    void restore();
    void cancel();
    State state() const { return current; }
    QUuid owner() const { return connection; }
    // Borrowed, nonblocking; a core duplicate must close before overall shutdown completes.
    int descriptor() const { return device; }
signals:
    void stateChanged(LinuxNetworkHelperClient::State state);
    void finished(LinuxNetworkHelperClient::Operation operation, PlatformOperationResult result);
    void ownershipLost(PlatformOperationResult result);
private:
    void begin(const QUuid &owner, Operation operation, QJsonObject request);
    void inspected(int exitCode, QProcess::ExitStatus status);
    void authorize();
    void accept();
    void receive();
    void exited(quint64 serial, pid_t process, int status);
    void timeout();
    void setState(State state);
    void closeChannels();
    void restoreActive();
    void finish(PlatformOperationResult result, State state);
    void failed(const QString &detail);
    State retryState() const;
    bool send(const QJsonObject &packet);
    QJsonObject command(const char *operation) const;
    QProcess probe;
    QTimer deadline;
    QSocketNotifier *listener = nullptr, *receiver = nullptr;
    int server = -1, control = -1, device = -1;
    pid_t child = -1;
    quint64 generation = 0;
    State current = State::Idle;
    Operation operation = Operation::Apply;
    QUuid connection;
    QJsonObject initial;
    std::optional<PlatformOperationResult> outcome;
};
