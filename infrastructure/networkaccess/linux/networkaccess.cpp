#include "infrastructure/networkaccess/linux/networkaccess.h"
#include "infrastructure/dns/dnsroutepublisher.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include "infrastructure/networkhelper/linux/networkownership.h"
#include "application/networkprotection.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QtConcurrent>
#include <unistd.h>

using Result = PlatformOperationResult;
using Status = Result::Status;
using HelperState = LinuxNetworkHelperClient::State;
using Operation = LinuxNetworkHelperClient::Operation;

LinuxNetworkAccess::LinuxNetworkAccess(CoreEngine *core, NetworkPolicySession *policy, int mtu, QObject *parent)
    : NetworkAccess(parent), core(core), policy(policy), mtu(mtu)
{
    new DNSRoutePublisher<LinuxNetworkHelperClient>(core, &helper, this, [this] { return stage == Stage::Ready; });
    connect(&helper, &LinuxNetworkHelperClient::finished, this, &LinuxNetworkAccess::helperFinished);
    connect(&helper, &LinuxNetworkHelperClient::stateChanged, this, [this](HelperState state) {
        if (state != HelperState::Idle && state != HelperState::Active)
            this->policy->setNetworkBusy(generation, true);
    });
    connect(&helper, &LinuxNetworkHelperClient::ownershipLost, this, [this](Result result) {
        if (stage == Stage::Ready || stage == Stage::Updating) { stage = Stage::Failed; emit lost(attempt, result); }
    });
    connect(policy, &NetworkPolicySession::changed, this, &LinuxNetworkAccess::prepareConfiguration);
    connect(policy, &NetworkPolicySession::changed, this, &LinuxNetworkAccess::observeModel, Qt::QueuedConnection);
    // Bound stale protection without overlapping native reads or introducing another policy owner.
    observation.setInterval(2000);
    connect(&observation, &QTimer::timeout, this, [this] {
        if (stage == Stage::Ready && !this->policy->isBusy()) this->policy->refresh();
    });
    connect(&worker, &QFutureWatcher<LinuxHelperPreparation>::finished, this, [this] {
        preparingConfiguration = false;
        if (stage == Stage::Stopping) { driveStop(); return; }
        if (stage != Stage::Activating && stage != Stage::Updating) return;
        const auto prepared = worker.result();
        if (stage == Stage::Updating) {
            if (prepared.result.succeeded()) this->core->updatePolicy(changingPolicy);
            else {
                finishPolicy(CoreEngine::RequestStatus::Unavailable);
            }
            return;
        }
        if (!prepared.result.succeeded()) { stage = Stage::Prepared; this->policy->setNetworkBusy(generation, false); emit ready(attempt, prepared.result); return; }
        const auto exit = linuxOriginalExitSnapshot(activationNetwork,prepared.configuration);
        if (!exit) { stage = Stage::Prepared; this->policy->setNetworkBusy(generation,false);
            emit ready(attempt,{Status::Failed,QStringLiteral("无法确认原网络出口的完整读取范围。")});return; }
        originalExit = *exit;
        activationNetwork = {};
        const auto saved = saveOwner(attempt);
        if (!saved.succeeded()) { stage = Stage::Prepared; this->policy->setNetworkBusy(generation, false); emit ready(attempt, saved); return; }
        helper.apply(attempt, prepared.configuration);
    });
    connect(core, &CoreEngine::tunAttached, this, [this](const QString &id, CoreEngine::RequestStatus status) {
        if (stage != Stage::Activating || !attaching || id != generation) return;
        attaching = false;
        stage = status == CoreEngine::RequestStatus::Success ? Stage::Ready : Stage::Prepared;
        if (stage == Stage::Ready) {
            this->policy->setPolicyApplier(generation, [this](const QJsonObject &value) { applyPolicy(value); });
            observation.start();
        }
        emit ready(attempt, status == CoreEngine::RequestStatus::Success ? Result{}
            : Result{Status::Failed, QStringLiteral("核心未能接收已授权的网络设备。")});
    });
    connect(core, &CoreEngine::policyUpdated, this, [this](const QString &id, const QString &revision, CoreEngine::RequestStatus status) {
        if (stage != Stage::Updating || id != generation || revision != changingPolicy["revision"].toString()) return;
        if (status == CoreEngine::RequestStatus::Success) helper.reconcile(nextCapture);
        else {
            finishPolicy(status);
        }
    });
}

LinuxNetworkAccess::~LinuxNetworkAccess() { worker.waitForFinished(); }

void LinuxNetworkAccess::prepare(const QUuid &id)
{
    if (stage != Stage::Idle || id.isNull()) {
        emit prepared(id, {Status::Failed, QStringLiteral("上一连接的网络恢复尚未完成。"), true}); return;
    }
    attempt = id;
    stage = Stage::Preparing;
    const auto scope = linuxNetworkNamespace();
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/network-owners";
    if (scope.isEmpty() || !QDir().mkpath(directory) || QFileInfo(directory).isSymLink()
        || QFileInfo(directory).ownerId() != ::getuid()
        || !QFile::setPermissions(directory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner)) {
        stage = Stage::Prepared;
        emit prepared(id, {Status::Failed, QStringLiteral("无法创建当前账户的网络责任记录目录。")}); return;
    }
    const auto key = QCryptographicHash::hash(scope.toUtf8(), QCryptographicHash::Sha256).toHex();
    hint = QDir(directory).filePath(QString::fromLatin1(key) + ".owner");
    lock = std::make_unique<QLockFile>(hint + ".lock");
    lock->setStaleLockTime(0);
    if (!lock->tryLock()) {
        stage = Stage::Prepared;
        emit prepared(id, {Status::Failed, QStringLiteral("当前网络命名空间已有 JustConnect 连接或恢复操作。")}); return;
    }
    QFile file(hint);
    const auto info = QFileInfo(hint);
    if (!info.exists() && !info.isSymLink()) { stage = Stage::Prepared; emit prepared(id, {}); return; }
    if (!info.isFile() || info.isSymLink() || info.ownerId() != ::getuid() || info.size() != 36
        || !file.open(QIODevice::ReadOnly)) {
        stage = Stage::Failed;
        emit prepared(id, {Status::Failed, QStringLiteral("网络责任记录无效，请保留记录并检查安装。"), true}); return;
    }
    const auto text = file.read(37);
    savedOwner = QUuid(text);
    if (savedOwner.isNull() || savedOwner.toByteArray(QUuid::WithoutBraces) != text) {
        savedOwner = {};
        stage = Stage::Failed;
        emit prepared(id, {Status::Failed, QStringLiteral("网络责任记录包含无效的连接标识。"), true}); return;
    }
    // This UUID is only a hint; the privileged helper validates its own ownership journals.
    helper.recover(savedOwner);
}

Result LinuxNetworkAccess::saveOwner(const QUuid &owner)
{
    if (!lock || !lock->isLocked()) return {Status::Failed, QStringLiteral("未取得网络责任锁。")};
    QSaveFile file(hint);
    file.setDirectWriteFallback(false);
    const auto bytes = owner.toByteArray(QUuid::WithoutBraces);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || file.write(bytes) != bytes.size() || !file.commit())
        return {Status::Failed, QStringLiteral("无法在接管前保存网络责任标识。")};
    savedOwner = owner;
    return {};
}

void LinuxNetworkAccess::activate(const QUuid &id, const ConnectionProfile &profile)
{
    if (id != attempt || stage != Stage::Prepared || !lock || !lock->isLocked()) {
        emit ready(id, {Status::Failed, QStringLiteral("网络准备阶段尚未完成。")}); return;
    }
    stage = Stage::Activating;
    localDNS = profile.dns.localDnsServer;
    generation = policy->currentGeneration();
    prepareConfiguration();
}

void LinuxNetworkAccess::prepareConfiguration()
{
    if (stage != Stage::Activating || preparingConfiguration || attaching || !savedOwner.isNull()) return;
    if (policy->isBusy() || policy->status() == CoreEngine::RequestStatus::Pending) return;
    if (policy->status() != CoreEngine::RequestStatus::Success || policy->currentGeneration() != generation
        || policy->confirmedProtection().isEmpty()) {
        stage = Stage::Prepared;
        emit ready(attempt, {Status::Failed, QStringLiteral("无法取得完整且已确认的原网络保护策略。")}); return;
    }
    const auto model = policy->model(), confirmed = policy->confirmedProtection();
    activationNetwork = model["network"].toObject();
    preparingConfiguration = true;
    policy->setNetworkBusy(generation, true);
    worker.setFuture(QtConcurrent::run([model, confirmed, dns = localDNS, mtu = mtu] {
        return prepareLinuxNetworkHelper(model["resources"].toObject(), confirmed, model["network"].toObject(),
            DnsSnapshot{{}, model["dns"].toObject()}, dns, mtu);
    }));
}

void LinuxNetworkAccess::applyPolicy(const QJsonObject &value)
{
    const auto owned = helper.ownedConfiguration();
    const auto capture = owned ? updatedCampusCapturePrefixes(policy->model()["resources"].toObject(),
        value,owned->dnsDomains) : std::nullopt;
    if (stage != Stage::Ready || helper.state() != HelperState::Active || !capture) {
        policy->completePolicy(value["generation"].toString(),value["revision"].toString(),CoreEngine::RequestStatus::Unavailable);
        return;
    }
    changingPolicy = value; nextCapture = *capture; stage = Stage::Updating;
    policy->setNetworkBusy(generation,true);
    preparingConfiguration = true;
    worker.setFuture(QtConcurrent::run([configuration=*owned,prefixes=*capture] {
        return LinuxHelperPreparation{verifyLinuxCaptureExit(configuration,prefixes),{}};
    }));
}

void LinuxNetworkAccess::observeModel()
{
    if (stage != Stage::Ready || automaticPolicy || policy->isBusy()) return;
    const auto owned = helper.ownedConfiguration();
    const auto current = owned ? linuxOriginalExitSnapshot(policy->model()["network"].toObject(),*owned) : std::nullopt;
    if (policy->status() != CoreEngine::RequestStatus::Success || !owned) {
        invalidateNetwork(QStringLiteral("无法完整读取原网络，正在恢复网络。"));
        return;
    }
    if (!current || *current != originalExit) {
        observation.stop();
        stage = Stage::Prepared;
        emit restartRequired(attempt,QStringLiteral("原网络出口已变化，正在恢复网络。"));
        return;
    }
    const auto prefixes = updatedCampusCapturePrefixes(policy->model()["resources"].toObject(),policy->confirmedProtection(),owned->dnsDomains);
    if (!prefixes) { invalidateNetwork(QStringLiteral("无法确认当前校园捕获范围。")); return; }
    auto actual = owned->capturePrefixes, expected = *prefixes; actual.sort(); expected.sort();
    if (actual != expected) { helper.reconcile(*prefixes); return; }
    automaticPolicy = true;
    const auto result = policy->synchronizeProtection();
    if (result == CoreEngine::RequestStatus::Pending) return;
    automaticPolicy = false;
    if (result != CoreEngine::RequestStatus::Success)
        invalidateNetwork(QStringLiteral("新的网络或 DNS 保护范围无法安全生效，正在恢复原网络。"));
}

void LinuxNetworkAccess::finishPolicy(CoreEngine::RequestStatus status)
{
    const auto revision = changingPolicy["revision"].toString();
    const bool automatic = automaticPolicy;
    changingPolicy = {}; nextCapture.clear(); stage = Stage::Ready;
    policy->setNetworkBusy(generation,false);
    policy->completePolicy(generation,revision,status);
    automaticPolicy = false;
    if (automatic && status != CoreEngine::RequestStatus::Success && stage == Stage::Ready)
        invalidateNetwork(QStringLiteral("新的网络或 DNS 保护策略未能确认，正在恢复原网络。"));
}

void LinuxNetworkAccess::invalidateNetwork(const QString &detail)
{
    observation.stop();
    stage = Stage::Prepared;
    emit lost(attempt,{Status::Failed,detail,true});
}

void LinuxNetworkAccess::helperFinished(Operation operation, Result result)
{
    if ((operation == Operation::Apply || operation == Operation::Extend || operation == Operation::Routes) && result.succeeded()
        && helper.state() == HelperState::Active && (stage == Stage::Ready || stage == Stage::Updating || stage == Stage::Activating)) {
        if (operation == Operation::Extend && !result.mayHaveChanged) {
            policy->setNetworkBusy(generation, false);
            return;
        }
        const auto configuration = helper.ownedConfiguration();
        const auto filter = configuration ? linuxOriginalNetworkView(helper.owner(), *configuration, helper.ownedDevice(),
            int(::if_nametoindex(configuration->originalInterface.toLatin1().constData()))) : NetworkPolicySession::OriginalViewFilter{};
        if (!filter) { stage = Stage::Failed; emit lost(attempt, {Status::Failed, QStringLiteral("无法识别活动网络接管的读取范围。"), true}); return; }
        policy->setOriginalViewFilter(generation, filter);
        policy->setNetworkBusy(generation, false);
    }
    if (operation == Operation::Routes && stage == Stage::Updating) {
        const auto revision = changingPolicy["revision"].toString();
        changingPolicy = {}; nextCapture.clear();automaticPolicy = false;
        stage = result.succeeded() ? Stage::Ready : helper.state() == HelperState::Idle ? Stage::Prepared : Stage::Failed;
        if (!result.succeeded()) emit lost(attempt,result);
        policy->completePolicy(generation,revision,result.succeeded() ? CoreEngine::RequestStatus::Success : CoreEngine::RequestStatus::Failed);
        return;
    }
    if ((operation == Operation::Extend || operation == Operation::Routes) && stage == Stage::Ready) {
        if (!result.succeeded()) { stage = Stage::Failed; emit lost(attempt, result); }
        return;
    }
    if (stage == Stage::Stopping) { completeStop(); return; }
    if (stage == Stage::Preparing) {
        if (result.succeeded() && helper.state() == HelperState::Idle) {
            QFile file(hint);
            if (!file.open(QIODevice::ReadOnly) || file.read(37) != savedOwner.toByteArray(QUuid::WithoutBraces)
                || !file.remove()) result = {Status::Failed, QStringLiteral("原网络已恢复，但责任标识未能清理。"), true};
            else savedOwner = {};
        }
        stage = result.succeeded() ? Stage::Prepared : Stage::Failed;
        emit prepared(attempt, result);
    } else if (stage == Stage::Activating && operation == Operation::Apply) {
        if (!result.succeeded()) { stage = Stage::Prepared; policy->setNetworkBusy(generation, false); emit ready(attempt, result); return; }
        attaching = true;
        core->attachTUN(generation, helper.descriptor(), quint32(mtu), true);
    }
}

void LinuxNetworkAccess::stop(const QUuid &id)
{
    if (id != attempt) { emit stopped(id, {Status::Failed, QStringLiteral("恢复请求不属于当前连接。"), true}); return; }
    if (stage == Stage::Stopping) return;
    observation.stop();
    const bool failedRecovery = stage == Stage::Failed;
    stage = Stage::Stopping;
    stopElapsed.start();
    // A denied recovery is retried only through the next explicit stop request.
    if (failedRecovery) {
        stage = Stage::Prepared;
        emit stopped(id, {Status::Failed, QStringLiteral("网络责任尚未解除；请重试断开并完成系统授权。"), true}); return;
    }
    driveStop();
}

void LinuxNetworkAccess::driveStop()
{
    if (stage != Stage::Stopping || preparingConfiguration) return;
    if (helper.state() == HelperState::Idle) { completeStop(); return; }
    if ((helper.state() == HelperState::RecoveryRequired || helper.state() == HelperState::CleanupRequired)
        && helper.hasPendingProcess()) {
        if (stopElapsed.elapsed() >= LinuxRouteOperationTimeoutMs) {
            stage = Stage::Prepared;
            emit stopped(attempt, {Status::TimedOut, QStringLiteral("等待网络助手结束超时，责任记录已保留。"), true}); return;
        }
        QTimer::singleShot(20, this, &LinuxNetworkAccess::driveStop);
        return;
    }
    helper.restore();
}

void LinuxNetworkAccess::completeStop()
{
    if (helper.state() != HelperState::Idle) {
        stage = Stage::Prepared;
        emit stopped(attempt, {Status::Failed, QStringLiteral("网络恢复或完成证明尚未确认，责任记录已保留。"), true}); return;
    }
    if (!savedOwner.isNull()) {
        QFile file(hint);
        if (!file.open(QIODevice::ReadOnly) || file.read(37) != savedOwner.toByteArray(QUuid::WithoutBraces) || !file.remove()) {
            stage = Stage::Prepared;
            emit stopped(attempt, {Status::Failed, QStringLiteral("网络已恢复，责任标识清理失败。"), true}); return;
        }
        savedOwner = {};
    } else if (stage == Stage::Stopping && lock && lock->isLocked() && (QFileInfo::exists(hint) || QFileInfo(hint).isSymLink())) {
        stage = Stage::Prepared;
        emit stopped(attempt, {Status::Failed, QStringLiteral("未知网络责任记录已保留，未猜测恢复。"), true}); return;
    }
    lock.reset();
    stage = Stage::Idle;
    attaching = automaticPolicy = false;
    changingPolicy = originalExit = activationNetwork = {};nextCapture.clear();
    emit stopped(attempt, {});
}
