#pragma once
#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "networkhelperclient.h"
#include "networkhelperpreparation.h"
#include <QFutureWatcher>
#include <QLockFile>

class MacNetworkAccess final : public NetworkAccess
{
public:
    MacNetworkAccess(CoreEngine *core,NetworkPolicySession *policy,int mtu,QObject *parent = nullptr,
        MacNetworkHelperClient::AuthorizationProvider authorization = {});
    ~MacNetworkAccess() override;
    void prepare(const QUuid &attempt) override;
    void activate(const QUuid &attempt,const ConnectionProfile &profile) override;
    void stop(const QUuid &attempt) override;
private:
    enum class Stage { Idle, Preparing, Prepared, Activating, Ready, Stopping };
    void prepareConfiguration();
    void helperFinished(MacNetworkHelperClient::Operation operation,PlatformOperationResult result);
    void driveStop();
    void observeModel();
    CoreEngine *core;
    NetworkPolicySession *policy;
    const int mtu;
    MacNetworkHelperClient helper;
    QFutureWatcher<MacHelperPreparation> worker;
    std::unique_ptr<QLockFile> lock;
    QUuid attempt;
    QString generation,localDNS;
    Stage stage = Stage::Idle;
    QTimer observation;
    bool preparing = false,attaching = false,automaticPolicy = false;
};
