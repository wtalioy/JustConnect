#include "infrastructure/networkaccess/windows/networkaccess.h"
#include "application/networkprotection.h"
#include "infrastructure/routing/originalexit.h"
#include "infrastructure/dns/dnsroutepublisher.h"
#include "infrastructure/dns/dnssnapshot.h"
#include <QDir>
#include <QStandardPaths>
#include <QLoggingCategory>
#include <QtConcurrent>
#include <utility>

using Result=PlatformOperationResult;
using Status=Result::Status;
using HelperState=WindowsNetworkHelperClient::State;
using Operation=WindowsNetworkHelperClient::Operation;
Q_LOGGING_CATEGORY(windowsNetworkAccessLog,"justconnect.networkaccess.windows",QtWarningMsg)

WindowsNetworkAccess::WindowsNetworkAccess(CoreEngine *core,NetworkPolicySession *policy,int mtu,QObject *parent,
    WindowsNetworkHelperClient::AuthorizationProvider authorization)
    :NetworkAccess(parent),core(core),policy(policy),mtu(mtu),helper(nullptr,std::move(authorization))
{
    connect(&helper,&WindowsNetworkHelperClient::finished,this,&WindowsNetworkAccess::helperFinished);
    connect(&helper,&WindowsNetworkHelperClient::ownershipLost,this,&WindowsNetworkAccess::fail);
    connect(&helper,&WindowsNetworkHelperClient::stateChanged,this,[this](HelperState state){
        if(state!=HelperState::Idle && state!=HelperState::Ready && state!=HelperState::Active)
            this->policy->setNetworkBusy(generation,true);
    });
    new DNSRoutePublisher<WindowsNetworkHelperClient>(core,&helper,this,[this]{return stage==Stage::Ready;});
    connect(policy,&NetworkPolicySession::changed,this,&WindowsNetworkAccess::prepareConfiguration);
    connect(policy,&NetworkPolicySession::changed,this,&WindowsNetworkAccess::observeModel,Qt::QueuedConnection);
    observation.setInterval(2000);
    connect(&observation,&QTimer::timeout,this,[this]{if(stage==Stage::Ready && !this->policy->isBusy())this->policy->refresh();});
    connect(&preparation,&QFutureWatcher<WindowsHelperPreparation>::finished,this,[this]{
        preparing=false;
        if(stage==Stage::Stopping){driveStop();return;}
        if(stage!=Stage::Activating)return;
        const auto result=preparation.result();
        if(!result.result.succeeded()){fail(result.result);return;}
        mutationPossible=true;helper.apply(result.configuration);
    });
    connect(&dnsReader,&QFutureWatcher<DnsSnapshot>::finished,this,[this]{
        readingDNS=false;
        if(stage==Stage::Stopping)driveStop();
        else if(stage==Stage::Activating){if(!dnsReader.result().result.succeeded())fail(dnsReader.result().result);else finishOwnership();}
    });
    connect(core,&CoreEngine::sessionStarted,this,[this]{coreRunning=true;});
    connect(core,&CoreEngine::finished,this,[this]{coreRunning=false;if(stage==Stage::Stopping)driveStop();});
    connect(core,&CoreEngine::snapshotReady,this,[this](CoreEngine::Snapshot kind,const QString &id,const QJsonObject &value,CoreEngine::RequestStatus status){
        if(stage!=Stage::Activating || !readingNetwork || id!=generation || kind!=CoreEngine::Snapshot::Network)return;
        readingNetwork=false;
        if(status!=CoreEngine::RequestStatus::Success || !value["network"].isObject()){
            fail({Status::Failed,"Cannot confirm the active private network device.",true});return;
        }
        ownedNetwork=value["network"].toObject();finishOwnership();
    });
    connect(core,&CoreEngine::tunAttached,this,[this](const QString &id,CoreEngine::RequestStatus status){
        if(stage!=Stage::Activating || !attaching || id!=generation)return;
        attaching=false;
        if(status!=CoreEngine::RequestStatus::Success){fail({Status::Failed,"The core could not accept the authorized network device.",true});return;}
        stage=Stage::Ready;this->policy->setPolicyApplier(generation,[this](const QJsonObject &value){applyPolicy(value);});
        observation.start();emit ready(attempt,{});
    });
    connect(core,&CoreEngine::policyUpdated,this,[this](const QString &id,const QString &revision,CoreEngine::RequestStatus status){
        if(stage!=Stage::Updating || id!=generation || revision!=changingPolicy["revision"].toString())return;
        if(status==CoreEngine::RequestStatus::Success)helper.reconcile(nextCapture);else finishPolicy(status);
    });
}
WindowsNetworkAccess::~WindowsNetworkAccess(){preparation.waitForFinished();dnsReader.waitForFinished();}

void WindowsNetworkAccess::prepare(const QUuid &id)
{
    if(stage!=Stage::Idle || id.isNull()){emit prepared(id,{Status::Failed,"Previous network recovery is incomplete.",true});return;}
    attempt=id;stage=Stage::Preparing;
    const auto directory=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)+"/network-owners";
    if(!QDir().mkpath(directory)){fail({Status::Failed,"Cannot prepare the current account's connection lock."});return;}
    // This account-local lock only coordinates GUI instances; the native machine journal grants recovery authority.
    lock=std::make_unique<QLockFile>(QDir(directory).filePath("windows.lock"));lock->setStaleLockTime(0);
    if(!lock->tryLock()){fail({Status::Failed,"This account already has a JustConnect connection or recovery operation."});return;}
    helper.inspect(attempt);
}
void WindowsNetworkAccess::activate(const QUuid &id,const ConnectionProfile &profile)
{
    if(id!=attempt || stage!=Stage::Prepared || !lock || !lock->isLocked()){
        emit ready(id,{Status::Failed,"Network preparation is incomplete."});return;
    }
    stage=Stage::Activating;generation=policy->currentGeneration();localDNS=profile.dns.localDnsServer;prepareConfiguration();
}
void WindowsNetworkAccess::prepareConfiguration()
{
    if(stage!=Stage::Activating || preparing || attaching || readingDNS || readingNetwork || helper.state()!=HelperState::Ready)return;
    if(policy->isBusy() || policy->status()==CoreEngine::RequestStatus::Pending)return;
    if(policy->status()!=CoreEngine::RequestStatus::Success || policy->currentGeneration()!=generation || policy->confirmedProtection().isEmpty()){
        fail({Status::Failed,"Cannot confirm complete original-network protection."});return;
    }
    const auto model=policy->model(),confirmed=policy->confirmedProtection();
    const auto exit=originalExitSnapshot(model["network"].toObject(),model["resources"].toObject()["underlay_interface"].toString());
    if(!exit){fail({Status::Failed,"Cannot confirm the original network exit."});return;}
    originalExit=*exit;preparing=true;policy->setNetworkBusy(generation,true);
    preparation.setFuture(QtConcurrent::run([model,confirmed,dns=localDNS,mtu=mtu]{
        return prepareWindowsNetworkHelper(model["resources"].toObject(),confirmed,model["network"].toObject(),model["dns"].toObject(),dns,mtu);
    }));
}
void WindowsNetworkAccess::inspectOwners()
{
    const auto owners=helper.pendingOwners();
    if(owners.isEmpty()){
        mutationPossible=false;receipt={};
        if(stage==Stage::Preparing){stage=Stage::Prepared;emit prepared(attempt,{});}else driveStop();
        return;
    }
    mutationPossible=true;
    const auto record=owners.first().toObject();receipt=QUuid(record["owner"].toString());
    if(record["phase"]=="restored")helper.cleanupRestored(receipt);
    else if(record["live"]==true)fail({Status::Failed,"Previous network ownership is still active; retry recovery after its helper exits.",true});
    else helper.recover(receipt);
}
void WindowsNetworkAccess::helperFinished(Operation operation,Result result)
{
    if(stage==Stage::Idle || stage==Stage::Prepared)return;
    if(!result.succeeded()){
        if(stage==Stage::Stopping && !mutationPossible && result.status==Status::Cancelled){driveStop();return;}
        fail(result);return;
    }
    if(stage==Stage::Preparing || stage==Stage::Stopping){
        if(operation==Operation::Inspect){inspectOwners();return;}
        if(operation==Operation::Recover){helper.cleanupRestored(receipt);return;}
        if(operation==Operation::Acknowledge){receipt={};helper.inspect(attempt);return;}
        if(operation==Operation::Restore)receipt=attempt;
        driveStop();return;
    }
    if(operation==Operation::Apply && stage==Stage::Activating){
        readingDNS=readingNetwork=true;
        dnsReader.setFuture(QtConcurrent::run(readSystemDnsSnapshot));
        core->readSnapshot(CoreEngine::Snapshot::Network,generation);return;
    }
    if(operation==Operation::Extend || operation==Operation::Routes){
        if(!updateOriginalView())return;
        if(stage==Stage::Updating){
            const auto revision=changingPolicy["revision"].toString();changingPolicy={};nextCapture.clear();automaticPolicy=false;
            stage=Stage::Ready;policy->completePolicy(generation,revision,CoreEngine::RequestStatus::Success);
        }
    }
}
void WindowsNetworkAccess::finishOwnership()
{
    if(stage!=Stage::Activating || readingNetwork || readingDNS || attaching)return;
    ownership=WindowsNetworkOwnership::capture(helper.ownedConfiguration(),helper.ownedDevice(),ownedNetwork,dnsReader.result().data);
    if(!ownership || !updateOriginalView()){
        if(!ownership)fail({Status::Failed,"Cannot identify the confirmed private-device and DNS read scope.",true});
        return;
    }
    attaching=true;const auto device=helper.ownedDevice();
    core->attachWindowsPipe(generation,helper.packetPipeHandle(),helper.helperPID(),quint32(mtu),device["address"].toString(),device["peer"].toString(),true);
}
bool WindowsNetworkAccess::updateOriginalView()
{
    const auto filter=ownership?ownership->filter(helper.ownedConfiguration()):NetworkPolicySession::OriginalViewFilter{};
    if(!filter){fail({Status::Failed,"Cannot identify the active network read scope.",true});return false;}
    policy->setOriginalViewFilter(generation,filter);policy->setNetworkBusy(generation,false);return true;
}
void WindowsNetworkAccess::fail(Result result)
{
    if(stage==Stage::Idle)return;
    const auto previous=stage;stage=Stage::Prepared;observation.stop();pendingFailure=result;
    policy->setNetworkBusy(generation,false);
    if(previous==Stage::Preparing)emit prepared(attempt,result);
    else if(previous==Stage::Activating)emit ready(attempt,result);
    else if(previous==Stage::Stopping){pendingFailure.reset();emit lost(attempt,result);emit stopped(attempt,result);}
    else emit lost(attempt,result);
}
void WindowsNetworkAccess::stop(const QUuid &id)
{
    if(id!=attempt){emit stopped(id,{Status::Failed,"Recovery does not belong to this connection.",true});return;}
    if(stage==Stage::Stopping)return;
    observation.stop();stage=Stage::Stopping;
    if(pendingFailure && mutationPossible && (helper.state()==HelperState::Idle || helper.state()==HelperState::Cancelling)){
        const auto result=*pendingFailure;pendingFailure.reset();stage=Stage::Prepared;
        emit lost(attempt,result);emit stopped(attempt,result);return;
    }
    pendingFailure.reset();driveStop();
}
void WindowsNetworkAccess::driveStop()
{
    if(stage!=Stage::Stopping || preparing || readingDNS)return;
    switch(helper.state()){
    case HelperState::Idle:
        if(mutationPossible){helper.inspect(attempt);return;}
        lock.reset();ownership.reset();generation.clear();receipt={};ownedNetwork=originalExit=changingPolicy={};nextCapture.clear();
        preparing=readingNetwork=attaching=quiesceReported=automaticPolicy=false;stage=Stage::Idle;emit stopped(attempt,{});return;
    case HelperState::Ready:
        if(!receipt.isNull()){helper.cleanupRestored(receipt);return;}
        if(mutationPossible){helper.inspect(attempt);return;}
        helper.close();return;
    case HelperState::Active:helper.quiesce();return;
    case HelperState::Quiesced:
        if(coreRunning){if(!quiesceReported){quiesceReported=true;emit quiesced(attempt);}return;}
        helper.restore();return;
    default:
        if(!mutationPossible)helper.cancel();return;
    }
}
void WindowsNetworkAccess::observeModel()
{
    if(stage!=Stage::Ready || automaticPolicy || policy->isBusy())return;
    if(policy->status()!=CoreEngine::RequestStatus::Success){fail({Status::Failed,"Cannot completely read the original network; restoring ownership.",true});return;}
    const auto model=policy->model();
    const auto exit=originalExitSnapshot(model["network"].toObject(),model["resources"].toObject()["underlay_interface"].toString());
    if(!exit || *exit!=originalExit){stage=Stage::Prepared;observation.stop();emit restartRequired(attempt,"Original network exit changed; restoring before reconnecting.");return;}
    QStringList domains;for(const auto &item:helper.ownedConfiguration()["dns_domains"].toArray())domains.append(item.toString());
    const auto prefixes=updatedCampusCapturePrefixes(model["resources"].toObject(),policy->confirmedProtection(),domains);
    if(!prefixes){fail({Status::Failed,"Cannot confirm current campus capture scope.",true});return;}
    QStringList actual;for(const auto &item:helper.ownedConfiguration()["capture_prefixes"].toArray())actual.append(item.toString());actual.sort();auto expected=*prefixes;expected.sort();
    if(actual!=expected){qCDebug(windowsNetworkAccessLog)<<"reconcile captures"<<actual<<"to"<<expected;helper.reconcile(*prefixes);return;}
    automaticPolicy=true;const auto status=policy->synchronizeProtection();
    if(status==CoreEngine::RequestStatus::Pending)return;
    automaticPolicy=false;
    if(status!=CoreEngine::RequestStatus::Success){stage=Stage::Prepared;observation.stop();emit restartRequired(attempt,"Original network protection changed; restoring before reconnecting.");}
}
void WindowsNetworkAccess::applyPolicy(const QJsonObject &value)
{
    qCDebug(windowsNetworkAccessLog)<<"apply policy"<<value;
    QStringList domains;for(const auto &item:helper.ownedConfiguration()["dns_domains"].toArray())domains.append(item.toString());
    const auto prefixes=updatedCampusCapturePrefixes(policy->model()["resources"].toObject(),value,domains);
    if(stage!=Stage::Ready || helper.state()!=HelperState::Active || !prefixes){
        const bool automatic=std::exchange(automaticPolicy,false);
        policy->completePolicy(value["generation"].toString(),value["revision"].toString(),CoreEngine::RequestStatus::Unavailable);
        if(automatic){stage=Stage::Prepared;observation.stop();emit restartRequired(attempt,"New protection could not be confirmed; restoring before reconnecting.");}
        return;
    }
    changingPolicy=value;nextCapture=*prefixes;stage=Stage::Updating;policy->setNetworkBusy(generation,true);core->updatePolicy(value);
}
void WindowsNetworkAccess::finishPolicy(CoreEngine::RequestStatus status)
{
    const auto revision=changingPolicy["revision"].toString();const bool automatic=std::exchange(automaticPolicy,false);
    changingPolicy={};nextCapture.clear();stage=Stage::Ready;policy->setNetworkBusy(generation,false);policy->completePolicy(generation,revision,status);
    if(automatic && status!=CoreEngine::RequestStatus::Success){stage=Stage::Prepared;observation.stop();emit restartRequired(attempt,"New protection failed; restoring before reconnecting.");}
}
