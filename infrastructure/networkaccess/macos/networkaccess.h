#pragma once
#include "application/connectionsession.h"
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/macos/networkhelperclient.h"
#include "infrastructure/networkhelper/macos/networkhelperpreparation.h"
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
    enum class Stage { Idle, Preparing, Prepared, Activating, Ready, Updating, Stopping };
    void prepareConfiguration();
    void helperFinished(MacNetworkHelperClient::Operation operation,PlatformOperationResult result);
    void driveStop();
    void observeModel();
    void applyPolicy(const QJsonObject &value);
    void finishPolicy(CoreEngine::RequestStatus status);
    CoreEngine *core;
    NetworkPolicySession *policy;
    const int mtu;
    MacNetworkHelperClient helper;
    QFutureWatcher<MacHelperPreparation> worker;
    std::unique_ptr<QLockFile> lock;
    QUuid attempt;
    QString generation,localDNS;
    QJsonObject changingPolicy, originalExit;
    QStringList nextCapture;
    Stage stage = Stage::Idle;
    QTimer observation;
    bool preparing = false,attaching = false,automaticPolicy = false;
};
