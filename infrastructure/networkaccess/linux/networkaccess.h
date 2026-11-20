#pragma once
#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "infrastructure/networkaccess/linux/networkmonitor.h"
#include "infrastructure/networkhelper/linux/networkhelperclient.h"
#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include <QFutureWatcher>
#include <QLockFile>

// Automatic (TUN) network access on Linux through the privileged helper:
// pkexec authorizes one helper process per application launch, the helper
// owns the TUN device, campus routes and DNS ownership, and hands the raw
// descriptor to the core over SCM_RIGHTS. Clones the macOS state machine
// minus original-DNS rewriting, which Linux v1 does not implement.
class LinuxNetworkAccess final : public NetworkAccess
{
public:
    LinuxNetworkAccess(CoreEngine *core, NetworkPolicySession *policy, QObject *parent = nullptr);
    ~LinuxNetworkAccess() override;
    void prepare(const QUuid &attempt) override;
    void activate(const QUuid &attempt, const ConnectionOptions &connectionOptions) override;
    void stop(const QUuid &attempt) override;
private:
    enum class Stage { Idle, Preparing, Prepared, Activating, Ready, Updating, Stopping };
    void prepareConfiguration();
    void helperFinished(LinuxNetworkHelperClient::Operation operation, PlatformOperationResult result);
    void driveStop();
    void observeModel();
    void applyPolicy(const QJsonObject &value);
    void finishPolicy(CoreEngine::RequestStatus status);
    CoreEngine *core;
    NetworkPolicySession *policy;
    int mtu = 0;
    LinuxNetworkHelperClient helper;
    QFutureWatcher<LinuxHelperPreparation> worker;
    std::unique_ptr<LinuxNetworkMonitor> monitor;
    std::unique_ptr<QLockFile> lock;
    QUuid attempt;
    QString generation, localDNS;
    QJsonObject changingPolicy, originalExit;
    QStringList nextCapture;
    Stage stage = Stage::Idle;
    bool preparing = false, attaching = false, automaticPolicy = false;
};
