#include "networkaccess.h"
#include "dnsroutepublisher.h"
#include "iprouteutility.h"
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
    new LinuxDNSRoutePublisher(core, &helper, this);
    connect(&helper, &LinuxNetworkHelperClient::finished, this, &LinuxNetworkAccess::helperFinished);
    connect(&helper, &LinuxNetworkHelperClient::ownershipLost, this, [this](Result result) {
        if (stage == Stage::Ready) { stage = Stage::Failed; emit lost(attempt, result); }
    });
    connect(policy, &NetworkPolicySession::changed, this, &LinuxNetworkAccess::prepareConfiguration);
    connect(&worker, &QFutureWatcher<LinuxHelperPreparation>::finished, this, [this] {
        preparingConfiguration = false;
        if (stage == Stage::Stopping) { driveStop(); return; }
        if (stage != Stage::Activating) return;
        const auto prepared = worker.result();
        if (!prepared.result.succeeded()) { stage = Stage::Prepared; emit ready(attempt, prepared.result); return; }
        const auto saved = saveOwner(attempt);
        if (!saved.succeeded()) { stage = Stage::Prepared; emit ready(attempt, saved); return; }
        helper.apply(attempt, prepared.configuration);
    });
    connect(core, &CoreEngine::tunAttached, this, [this](const QString &id, CoreEngine::RequestStatus status) {
        if (stage != Stage::Activating || !attaching || id != generation) return;
        attaching = false;
        stage = status == CoreEngine::RequestStatus::Success ? Stage::Ready : Stage::Prepared;
        emit ready(attempt, status == CoreEngine::RequestStatus::Success ? Result{}
            : Result{Status::Failed, QStringLiteral("核心未能接收已授权的网络设备。")});
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
    preparingConfiguration = true;
    worker.setFuture(QtConcurrent::run([model, confirmed, dns = localDNS, mtu = mtu] {
        return prepareLinuxNetworkHelper(model["resources"].toObject(), confirmed, model["network"].toObject(),
            DnsSnapshot{{}, model["dns"].toObject()}, dns, mtu);
    }));
}

void LinuxNetworkAccess::helperFinished(Operation operation, Result result)
{
    if (operation == Operation::Extend && stage == Stage::Ready) {
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
        if (!result.succeeded()) { stage = Stage::Prepared; emit ready(attempt, result); return; }
        attaching = true;
        core->attachTUN(generation, helper.descriptor(), quint32(mtu), true);
    }
}

void LinuxNetworkAccess::stop(const QUuid &id)
{
    if (id != attempt) { emit stopped(id, {Status::Failed, QStringLiteral("恢复请求不属于当前连接。"), true}); return; }
    if (stage == Stage::Stopping) return;
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
    attaching = false;
    emit stopped(attempt, {});
}
