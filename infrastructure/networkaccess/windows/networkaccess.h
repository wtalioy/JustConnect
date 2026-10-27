#pragma once
#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/windows/networkhelperclient.h"
#include "infrastructure/networkhelper/windows/networkhelperpreparation.h"
#include "infrastructure/networkhelper/windows/networkownership.h"
#include <QLockFile>

class WindowsNetworkAccess final : public NetworkAccess {
public:
    WindowsNetworkAccess(CoreEngine *core,NetworkPolicySession *policy,int mtu,QObject *parent=nullptr,
        WindowsNetworkHelperClient::AuthorizationProvider authorization={});
    ~WindowsNetworkAccess() override;
    void prepare(const QUuid &attempt) override;
    void activate(const QUuid &attempt,const ConnectionProfile &profile) override;
    void stop(const QUuid &attempt) override;
private:
    enum class Stage {Idle,Preparing,Prepared,Activating,Ready,Updating,Stopping};
    void prepareConfiguration();
    void helperFinished(WindowsNetworkHelperClient::Operation operation,PlatformOperationResult result);
    void inspectOwners();
    void finishOwnership();
    bool updateOriginalView();
    void fail(PlatformOperationResult result);
    void driveStop();
    void observeModel();
    void applyPolicy(const QJsonObject &value);
    void finishPolicy(CoreEngine::RequestStatus status);
    CoreEngine *core;
    NetworkPolicySession *policy;
    const int mtu;
    WindowsNetworkHelperClient helper;
    QFutureWatcher<WindowsHelperPreparation> preparation;
    QFutureWatcher<DnsSnapshot> dnsReader;
    std::unique_ptr<QLockFile> lock;
    std::optional<WindowsNetworkOwnership> ownership;
    std::optional<PlatformOperationResult> pendingFailure;
    std::optional<QJsonObject> pendingConfiguration;
    QJsonArray originalSources;
    QJsonObject originalContext;
    QUuid attempt,receipt;
    QString generation,localDNS;
    QJsonObject originalExit,ownedNetwork,changingPolicy;
    QStringList nextCapture;
    QTimer observation;
    Stage stage=Stage::Idle;
    bool preparing=false,readingDNS=false,readingNetwork=false,attaching=false;
    bool mutationPossible=false,coreRunning=false,quiesceReported=false,automaticPolicy=false;
};
