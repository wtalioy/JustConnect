#pragma once

#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "networkhelperclient.h"
#include "networkhelperpreparation.h"
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
private:
    enum class Stage { Idle, Preparing, Prepared, Activating, Ready, Updating, Stopping, Failed };
    void prepareConfiguration();
    void applyPolicy(const QJsonObject &policy);
    void driveStop();
    void completeStop();
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
    QJsonObject changingPolicy;
    QStringList nextCapture;
    Stage stage = Stage::Idle;
    bool preparingConfiguration = false, attaching = false;
    QElapsedTimer stopElapsed;
};
