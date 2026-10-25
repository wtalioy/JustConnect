#include "infrastructure/networkaccess/macos/networkaccess.h"
#include "infrastructure/networkhelper/macos/networkownership.h"
#include "infrastructure/routing/macos/tunroutes.h"
#include "application/networkprotection.h"
#include "infrastructure/dns/dnsroutepublisher.h"
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QtConcurrent>
#include <unistd.h>

using Result = PlatformOperationResult;
using Status = Result::Status;
using HelperState = MacNetworkHelperClient::State;
using Operation = MacNetworkHelperClient::Operation;

MacNetworkAccess::MacNetworkAccess(CoreEngine *core,NetworkPolicySession *policy,int mtu,QObject *parent,
    MacNetworkHelperClient::AuthorizationProvider authorization)
    : NetworkAccess(parent),core(core),policy(policy),mtu(mtu),helper(nullptr,std::move(authorization))
{
    connect(&helper,&MacNetworkHelperClient::finished,this,&MacNetworkAccess::helperFinished);
    connect(&helper,&MacNetworkHelperClient::stateChanged,this,[this](HelperState state) {
        if (state != HelperState::Idle && state != HelperState::Active) this->policy->setNetworkBusy(generation,true);
    });
    connect(&helper,&MacNetworkHelperClient::ownershipLost,this,[this](Result result) {
        if (stage == Stage::Ready || stage == Stage::Updating) { observation.stop(); stage = Stage::Prepared; emit lost(attempt,result); }
    });
    new DNSRoutePublisher<MacNetworkHelperClient>(core,&helper,this,[this] { return stage == Stage::Ready; });
    connect(policy,&NetworkPolicySession::changed,this,&MacNetworkAccess::prepareConfiguration);
    connect(policy,&NetworkPolicySession::changed,this,&MacNetworkAccess::observeModel,Qt::QueuedConnection);
    observation.setInterval(2000);
    connect(&observation,&QTimer::timeout,this,[this] { if (stage == Stage::Ready && !this->policy->isBusy()) this->policy->refresh(); });
    connect(&worker,&QFutureWatcher<MacHelperPreparation>::finished,this,[this] {
        preparing = false;
        if (stage == Stage::Stopping) { driveStop(); return; }
        if (stage != Stage::Activating) return;
        const auto value = worker.result();
        if (!value.result.succeeded()) {
            stage = Stage::Prepared; this->policy->setNetworkBusy(generation,false); emit ready(attempt,value.result); return;
        }
        helper.apply(attempt,value.configuration);
    });
    connect(core,&CoreEngine::tunAttached,this,[this](const QString &id,CoreEngine::RequestStatus status) {
        if (stage != Stage::Activating || !attaching || id != generation) return;
        attaching = false;
        if (status != CoreEngine::RequestStatus::Success) {
            stage = Stage::Prepared; emit ready(attempt,{Status::Failed,QStringLiteral("核心未能接收已授权的网络设备。"),true}); return;
        }
        stage = Stage::Ready;
        this->policy->setPolicyApplier(generation,[this](const QJsonObject &value) { applyPolicy(value); });
        observation.start(); emit ready(attempt,{});
    });
    connect(core,&CoreEngine::policyUpdated,this,[this](const QString &id,const QString &revision,CoreEngine::RequestStatus status) {
        if (stage != Stage::Updating || id != generation || revision != changingPolicy["revision"].toString()) return;
        if (status == CoreEngine::RequestStatus::Success) helper.reconcile(nextCapture);
        else finishPolicy(status);
    });
}
MacNetworkAccess::~MacNetworkAccess() { worker.waitForFinished(); }

void MacNetworkAccess::prepare(const QUuid &id)
{
    if (stage != Stage::Idle || id.isNull()) { emit prepared(id,{Status::Failed,QStringLiteral("上一连接的网络恢复尚未完成。"),true}); return; }
    attempt = id; stage = Stage::Preparing;
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)+"/network-owners";
    const auto boot = macBootSession();
    if (boot.isEmpty() || !QDir().mkpath(directory) || QFileInfo(directory).isSymLink() || QFileInfo(directory).ownerId() != ::getuid()
        || !QFile::setPermissions(directory,QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner)) {
        stage = Stage::Prepared; emit prepared(id,{Status::Failed,QStringLiteral("无法准备当前账户的网络责任锁。")}); return;
    }
    lock = std::make_unique<QLockFile>(QDir(directory).filePath("macos-"+boot+".lock")); lock->setStaleLockTime(0);
    if (!lock->tryLock()) { stage = Stage::Prepared; emit prepared(id,{Status::Failed,QStringLiteral("当前账户已有 JustConnect 连接或恢复操作。")}); return; }
    helper.inspect(attempt);
}
void MacNetworkAccess::activate(const QUuid &id,const ConnectionProfile &profile)
{
    if (id != attempt || stage != Stage::Prepared || !lock || !lock->isLocked()) {
        emit ready(id,{Status::Failed,QStringLiteral("网络准备阶段尚未完成。")}); return;
    }
    stage = Stage::Activating; generation = policy->currentGeneration(); localDNS = profile.dns.localDnsServer;
    prepareConfiguration();
}
void MacNetworkAccess::prepareConfiguration()
{
    if (stage != Stage::Activating || preparing || attaching || helper.state() != HelperState::Idle) return;
    if (policy->isBusy() || policy->status() == CoreEngine::RequestStatus::Pending) return;
    if (policy->status() != CoreEngine::RequestStatus::Success || policy->currentGeneration() != generation || policy->confirmedProtection().isEmpty()) {
        stage = Stage::Prepared; emit ready(attempt,{Status::Failed,QStringLiteral("无法取得完整且已确认的原网络保护策略。")}); return;
    }
    const auto model = policy->model(), confirmed = policy->confirmedProtection();
    const auto exit = macOriginalExitSnapshot(model["network"].toObject(),model["resources"].toObject()["underlay_interface"].toString());
    if (!exit) { stage = Stage::Prepared; emit ready(attempt,{Status::Failed,QStringLiteral("无法确认完整的原网络出口。")}); return; }
    originalExit = *exit;
    preparing = true; policy->setNetworkBusy(generation,true);
    worker.setFuture(QtConcurrent::run([model,confirmed,dns=localDNS,mtu=mtu] {
        return prepareMacNetworkHelper(model["resources"].toObject(),confirmed,model["network"].toObject(),model["dns"].toObject(),dns,mtu);
    }));
}
void MacNetworkAccess::helperFinished(Operation operation,Result result)
{
    if (stage == Stage::Stopping) {
        if (!result.succeeded() && result.status != Status::Cancelled) {
            stage = Stage::Prepared; emit stopped(attempt,result); return;
        }
        driveStop(); return;
    }
    if (stage == Stage::Preparing) {
        if (!result.succeeded()) { stage = Stage::Prepared; emit prepared(attempt,result); return; }
        if (operation != Operation::Inspect) { helper.inspect(attempt); return; }
        const auto receipts = helper.pendingOwners();
        if (receipts.isEmpty()) { stage = Stage::Prepared; emit prepared(attempt,{}); return; }
        const auto receipt = receipts.first().toObject(); const QUuid owner(receipt["owner"].toString());
        if (receipt["phase"] == "restored") helper.cleanupRestored(owner);
        else helper.recover(owner);
        return;
    }
    if (result.succeeded() && helper.state() == HelperState::Active && (operation == Operation::Apply || operation == Operation::Extend || operation == Operation::Routes)) {
        const auto configuration = helper.ownedConfiguration();
        const auto filter = configuration ? macOriginalNetworkView(helper.owner(),*configuration,helper.ownedDevice(),helper.ownedNetwork()) : NetworkPolicySession::OriginalViewFilter{};
        if (!filter) { stage = Stage::Prepared; emit lost(attempt,{Status::Failed,QStringLiteral("无法识别活动网络接管的读取范围。"),true}); return; }
        policy->setOriginalViewFilter(generation,filter); policy->setNetworkBusy(generation,false);
    }
    if (operation == Operation::Routes && stage == Stage::Updating) {
        const auto revision = changingPolicy["revision"].toString();
        changingPolicy = {}; nextCapture.clear(); automaticPolicy = false;
        stage = result.succeeded() ? Stage::Ready : Stage::Prepared;
        policy->setNetworkBusy(generation,false);
        if (!result.succeeded()) { observation.stop(); emit lost(attempt,result); }
        policy->completePolicy(generation,revision,result.succeeded() ? CoreEngine::RequestStatus::Success : CoreEngine::RequestStatus::Failed);
        return;
    }
    if ((operation == Operation::Extend || operation == Operation::Routes) && stage == Stage::Ready) {
        if (!result.succeeded()) { stage = Stage::Prepared; observation.stop(); emit lost(attempt,result); }
        return;
    }
    if (stage == Stage::Activating && operation == Operation::Apply) {
        if (!result.succeeded()) { stage = Stage::Prepared; policy->setNetworkBusy(generation,false); emit ready(attempt,result); return; }
        attaching = true; core->attachTUN(generation,helper.descriptor(),quint32(mtu),true);
    }
}
void MacNetworkAccess::observeModel()
{
    if (stage != Stage::Ready || automaticPolicy || policy->isBusy()) return;
    if (policy->status() != CoreEngine::RequestStatus::Success) {
        stage = Stage::Prepared; observation.stop(); emit lost(attempt,{Status::Failed,QStringLiteral("无法完整读取原网络，正在恢复网络。"),true}); return;
    }
    const auto model = policy->model();
    const auto exit = macOriginalExitSnapshot(model["network"].toObject(),model["resources"].toObject()["underlay_interface"].toString());
    if (!exit || *exit != originalExit) {
        stage = Stage::Prepared; observation.stop(); emit restartRequired(attempt,QStringLiteral("原网络出口已变化，正在恢复网络后重新连接。")); return;
    }
    const auto owned = helper.ownedConfiguration();
    const auto prefixes = owned ? updatedCampusCapturePrefixes(model["resources"].toObject(),policy->confirmedProtection(),owned->dnsDomains) : std::nullopt;
    if (!prefixes) { stage = Stage::Prepared; observation.stop(); emit lost(attempt,{Status::Failed,QStringLiteral("无法确认当前校园捕获范围。"),true}); return; }
    auto actual = owned->capturePrefixes, expected = *prefixes; actual.sort(); expected.sort();
    if (actual != expected) { helper.reconcile(*prefixes); return; }
    automaticPolicy = true;
    const auto result = policy->synchronizeProtection();
    if (result == CoreEngine::RequestStatus::Pending) return;
    automaticPolicy = false;
    if (result != CoreEngine::RequestStatus::Success) {
        stage = Stage::Prepared; observation.stop(); emit restartRequired(attempt,QStringLiteral("原网络保护无法确认，正在恢复网络。"));
    }
}
void MacNetworkAccess::applyPolicy(const QJsonObject &value)
{
    const auto owned = helper.ownedConfiguration();
    const auto prefixes = owned ? updatedCampusCapturePrefixes(policy->model()["resources"].toObject(),
        value,owned->dnsDomains) : std::nullopt;
    if (stage != Stage::Ready || helper.state() != HelperState::Active || !prefixes) {
        const bool automatic = automaticPolicy; automaticPolicy = false;
        policy->completePolicy(value["generation"].toString(),value["revision"].toString(),CoreEngine::RequestStatus::Unavailable);
        if (automatic) { stage = Stage::Prepared; observation.stop(); emit restartRequired(attempt,QStringLiteral("新的网络保护无法应用，正在恢复网络后重新连接。")); }
        return;
    }
    changingPolicy = value; nextCapture = *prefixes; stage = Stage::Updating;
    policy->setNetworkBusy(generation,true); core->updatePolicy(value);
}
void MacNetworkAccess::finishPolicy(CoreEngine::RequestStatus status)
{
    const auto revision = changingPolicy["revision"].toString();
    const bool automatic = automaticPolicy;
    changingPolicy = {}; nextCapture.clear(); automaticPolicy = false; stage = Stage::Ready;
    policy->setNetworkBusy(generation,false); policy->completePolicy(generation,revision,status);
    if (automatic && status != CoreEngine::RequestStatus::Success && stage == Stage::Ready) {
        stage = Stage::Prepared; observation.stop(); emit restartRequired(attempt,QStringLiteral("新的网络保护未能确认，正在恢复网络后重新连接。"));
    }
}
void MacNetworkAccess::stop(const QUuid &id)
{
    if (id != attempt) { emit stopped(id,{Status::Failed,QStringLiteral("恢复请求不属于当前连接。"),true}); return; }
    if (stage == Stage::Stopping) return;
    observation.stop(); stage = Stage::Stopping; driveStop();
}
void MacNetworkAccess::driveStop()
{
    if (stage != Stage::Stopping || preparing) return;
    switch (helper.state()) {
    case HelperState::Idle:
        lock.reset(); stage = Stage::Idle; generation.clear(); changingPolicy = {}; nextCapture.clear(); originalExit = {}; attaching = automaticPolicy = false;
        emit stopped(attempt,{}); return;
    case HelperState::Active: helper.restore(); return;
    case HelperState::RecoveryRequired: helper.recover(helper.owner()); return;
    case HelperState::CleanupRequired: helper.cleanupRestored(helper.owner()); return;
    default: helper.cancel(); return;
    }
}
