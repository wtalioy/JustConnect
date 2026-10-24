#pragma once
#include "networkhelper.h"
#include <QObject>
#include <QTimer>
#include <Security/Authorization.h>
#include <functional>
#include <memory>

class MacNetworkHelperClient final : public QObject
{
    Q_OBJECT
public:
    enum class State { Idle, Inspecting, Registering, Authorizing, Applying, Active, Extending, Restoring, Acknowledging, RecoveryRequired, CleanupRequired };
    Q_ENUM(State)
    enum class Operation { Inspect, Apply, Extend, Restore, Recover, Cleanup };
    Q_ENUM(Operation)
    using AuthorizationProvider = std::function<OSStatus(AuthorizationRef *)>;
    explicit MacNetworkHelperClient(QObject *parent = nullptr, AuthorizationProvider authorization = {});
    ~MacNetworkHelperClient() override;
    void inspect(const QUuid &attempt);
    void apply(const QUuid &owner, const MacHelperConfiguration &configuration);
    void extend(const QStringList &addresses);
    void restore();
    void recover(const QUuid &owner);
    void cleanupRestored(const QUuid &owner);
    void cancel();
    State state() const { return current; }
    QUuid owner() const { return connection; }
    QJsonArray pendingOwners() const { return receipts; }
    std::optional<MacHelperConfiguration> ownedConfiguration() const { return device >= 0 ? std::optional(configuration) : std::nullopt; }
    QJsonObject ownedNetwork() const { return networkInfo; }
    QJsonObject ownedDevice() const { return deviceInfo; }
    // Borrowed fd; callers duplicate before returning to the event loop.
    int descriptor() const { return device; }
signals:
    void stateChanged(MacNetworkHelperClient::State state);
    void finished(MacNetworkHelperClient::Operation operation, PlatformOperationResult result);
    void ownershipLost(PlatformOperationResult result);
private:
    struct Native;
    void setState(State state);
    void finish(const PlatformOperationResult &result, State state);
    void send(const char *operation);
    void receive(const QJsonObject &request, const QJsonObject &response, std::shared_ptr<int> descriptor, bool trusted, bool unavailable = false);
    void probeFailed();
    void authorize();
    void disconnected(const QString &detail);
    void closeDevice();
    std::shared_ptr<Native> native;
    State current = State::Idle;
    Operation operation = Operation::Apply;
    QUuid connection, pendingRequest;
    MacHelperConfiguration configuration;
    QJsonObject deviceInfo, networkInfo;
    QJsonArray receipts;
    QStringList pendingExtension;
    QTimer deadline;
    int device = -1;
    bool cancelled = false, registered = false;
    PlatformOperationResult outcome;
};
