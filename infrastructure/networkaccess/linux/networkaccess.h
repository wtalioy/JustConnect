#pragma once

#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QLockFile>
#include <memory>

class LinuxNetworkAccess final : public NetworkAccess
{
public:
    LinuxNetworkAccess(CoreEngine *core, NetworkPolicySession *policy, int mtu, QObject *parent = nullptr);
    ~LinuxNetworkAccess() override;
    void prepare(const QUuid &attempt) override;
    void activate(const QUuid &attempt, const ConnectionProfile &profile) override;
    void stop(const QUuid &attempt) override;
    bool inspectProxyListeners(const QUuid &attempt, const QJsonObject &query) override;
private:
    enum class Stage { Idle, Preparing, Prepared, Activating, Ready, Updating, Stopping, Failed };
    void prepareConfiguration();
    void applyPreparedConfiguration(const LinuxHelperConfiguration &configuration);
    void applyPolicy(const QJsonObject &policy);
    void observeModel();
    void finishPolicy(CoreEngine::RequestStatus status);
    void invalidateNetwork(const QString &detail);
    void driveStop();
    void completeStop(PlatformOperationResult result = {});
    void helperFinished(LinuxNetworkHelperClient::Operation operation, PlatformOperationResult result);
    PlatformOperationResult saveOwner(const QUuid &owner);
    CoreEngine *core;
    NetworkPolicySession *policy;
    const int mtu;
    LinuxNetworkHelperClient helper;
    QFutureWatcher<LinuxHelperPreparation> worker;
    std::unique_ptr<QLockFile> lock;
    QUuid attempt, savedOwner;
    QString hint, generation, localDNS;
    QJsonObject changingPolicy, originalExit, activationNetwork;
    QTimer observation;
    QStringList nextCapture;
    QJsonArray originalSources;
    std::optional<LinuxHelperConfiguration> pendingConfiguration;
    Stage stage = Stage::Idle;
    bool preparingConfiguration = false, attaching = false, automaticPolicy = false;
    QElapsedTimer stopElapsed;
};
