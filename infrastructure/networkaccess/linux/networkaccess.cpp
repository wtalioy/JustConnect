#include "infrastructure/networkaccess/linux/networkaccess.h"
#include "infrastructure/networkaccess/linux/networkmonitor.h"
#include "infrastructure/networkhelper/linux/networkhelperavailability.h"
#include "infrastructure/networkhelper/linux/networkownership.h"
#include "application/campuscapture.h"
#include "infrastructure/dns/dnsroutepublisher.h"
#include "infrastructure/routing/originalexit.h"
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QtConcurrent>
#include <unistd.h>

using Result = PlatformOperationResult;
using Status = Result::Status;
using HelperState = LinuxNetworkHelperClient::State;
using Operation = LinuxNetworkHelperClient::Operation;

LinuxNetworkAccess::LinuxNetworkAccess(CoreEngine *core, NetworkPolicySession *policy, QObject *parent)
    : NetworkAccess(parent), core(core), policy(policy)
{
    connect(&helper, &LinuxNetworkHelperClient::finished, this, &LinuxNetworkAccess::helperFinished);
    connect(&helper, &LinuxNetworkHelperClient::stateChanged, this, [this](HelperState state) {
        if (state != HelperState::Idle && state != HelperState::Active) this->policy->setNetworkBusy(generation, true);
    });
    connect(&helper, &LinuxNetworkHelperClient::ownershipLost, this, [this](Result result) {
        if (stage == Stage::Activating) {
            stage = Stage::Prepared; emit ready(attempt, result);
        } else if (stage == Stage::Ready || stage == Stage::Updating) {
            stage = Stage::Prepared; emit lost(attempt, result);
        }
    });
    new DNSRoutePublisher<LinuxNetworkHelperClient>(core, &helper, this, [this] { return stage == Stage::Ready; },
        [this](const QStringList &addresses) -> std::optional<QStringList> {
            const auto owned = helper.ownedConfiguration();
            return owned ? excludeCampusCaptureAddresses(owned->capturePrefixes, addresses) : std::nullopt;
        });
    connect(policy, &NetworkPolicySession::changed, this, &LinuxNetworkAccess::prepareConfiguration);
    connect(policy, &NetworkPolicySession::changed, this, &LinuxNetworkAccess::observeModel, Qt::QueuedConnection);
    connect(&worker, &QFutureWatcher<LinuxHelperPreparation>::finished, this, [this] {
        preparing = false;
        if (stage == Stage::Stopping) { driveStop(); return; }
        if (stage != Stage::Activating) return;
        const auto value = worker.result();
        if (!value.result.succeeded()) {
            stage = Stage::Prepared; this->policy->setNetworkBusy(generation, false); emit ready(attempt, value.result); return;
        }
        helper.apply(attempt, value.configuration);
    });
    connect(core, &CoreEngine::tunAttached, this, [this](const QString &id, CoreEngine::RequestStatus status) {
        if (stage != Stage::Activating || !attaching || id != generation) return;
        attaching = false;
        if (status != CoreEngine::RequestStatus::Success) {
            // The helper still owns the device; the stop flow withdraws it.
            stage = Stage::Prepared; emit ready(attempt, {Status::Failed, QStringLiteral("Core could not receive the authorized network device."), true}); return;
        }
        stage = Stage::Ready;
        this->policy->setPolicyApplier(generation, [this](const QJsonObject &value) { applyPolicy(value); });
        emit ready(attempt, {});
    });
    connect(core, &CoreEngine::policyUpdated, this, [this](const QString &id, const QString &revision, CoreEngine::RequestStatus status) {
        if (stage != Stage::Updating || id != generation || revision != changingPolicy["revision"].toString()) return;
        if (status == CoreEngine::RequestStatus::Success) helper.reconcile(nextCapture);
        else finishPolicy(status);
    });
}

LinuxNetworkAccess::~LinuxNetworkAccess() { worker.waitForFinished(); }

void LinuxNetworkAccess::prepare(const QUuid &id)
{
    if (stage != Stage::Idle || id.isNull()) { emit prepared(id, {Status::Failed, QStringLiteral("Previous network recovery is incomplete."), true}); return; }
    // The attempt is owned before any early exit so a request to stop always
    // completes the teardown contract: ConnectionSession waits for a stopped
    // reply it recognizes, and a foreign or missing one leaves it in Stopping.
    attempt = id; stage = Stage::Preparing;
    // Automatic routing needs a root-owned helper, pkexec and a usable DNS
    // mechanism; report a missing one before any authorization prompt or
    // sign-in traffic instead of failing at the privileged step. The failure
    // diagnostic carries the concrete fix so connecting never dead-ends.
    const auto availability = linuxNetworkHelperAvailability();
    if (!availability.available) {
        stage = Stage::Prepared;
        const auto detail = availability.helperDetail.isEmpty() ? availability.routingDetail : availability.helperDetail;
        emit prepared(id, {Status::Unsupported, availability.remedy.isEmpty()
            ? detail : detail + QChar(' ') + availability.remedy});
        return;
    }
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/network-owners";
    if (!QDir().mkpath(directory) || QFileInfo(directory).isSymLink() || QFileInfo(directory).ownerId() != ::getuid()
        || !QFile::setPermissions(directory, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner)) {
        stage = Stage::Prepared; emit prepared(id, {Status::Failed, QStringLiteral("Cannot prepare the network ownership lock for this account.")}); return;
    }
    // The helper keeps its own write-ahead record under /run (tmpfs), so a
    // fixed per-account lock suffices; QLockFile clears crashed owners.
    lock = std::make_unique<QLockFile>(QDir(directory).filePath("linux.lock")); lock->setStaleLockTime(0);
    if (!lock->tryLock()) { stage = Stage::Prepared; emit prepared(id, {Status::Failed, QStringLiteral("This account already has a JustConnect connection or recovery operation.")}); return; }
    helper.inspect(attempt);
}

void LinuxNetworkAccess::activate(const QUuid &id, const ConnectionOptions &connectionOptions)
{
    if (id != attempt || stage != Stage::Prepared || !lock || !lock->isLocked()) {
        emit ready(id, {Status::Failed, QStringLiteral("Network preparation is incomplete.")}); return;
    }
    mtu = core->tunnelMtu();
    stage = Stage::Activating; generation = policy->currentGeneration(); localDNS = connectionOptions.dns.localDnsServer;
    monitor = std::make_unique<LinuxNetworkMonitor>(-1);
    connect(monitor.get(), &LinuxNetworkMonitor::networkChanged, this, [this] {
        if (stage == Stage::Ready || stage == Stage::Updating || helper.restorationPending())
            policy->requestRefresh();
    });
    prepareConfiguration();
}

void LinuxNetworkAccess::prepareConfiguration()
{
    if (stage != Stage::Activating || preparing || attaching || helper.state() != HelperState::Idle) return;
    if (policy->isBusy() || policy->status() == CoreEngine::RequestStatus::Pending) return;
    if (policy->status() != CoreEngine::RequestStatus::Success || policy->currentGeneration() != generation || policy->confirmedProtection().isEmpty()) {
        stage = Stage::Prepared; emit ready(attempt, {Status::Failed, QStringLiteral("Cannot obtain a complete confirmed original-network protection policy.")}); return;
    }
    const auto model = policy->model(), confirmed = policy->confirmedProtection();
    const auto exit = originalExitSnapshot(model["network"].toObject(), model["resources"].toObject()["underlay_interface"].toString());
    if (!exit) { stage = Stage::Prepared; emit ready(attempt, {Status::Failed, QStringLiteral("Cannot confirm the complete original network exit.")}); return; }
    originalExit = *exit;
    preparing = true; policy->setNetworkBusy(generation, true);
    worker.setFuture(QtConcurrent::run([model, confirmed, dns = localDNS, mtu = mtu] {
        return prepareLinuxNetworkHelper(model["resources"].toObject(), confirmed,
            model["network"].toObject(), model["dns"].toObject(), dns, mtu);
    }));
}

void LinuxNetworkAccess::helperFinished(Operation operation, Result result)
{
    if (stage == Stage::Stopping) {
        if (!result.succeeded() && (result.status != Status::Cancelled || operation == Operation::Inspect)) {
            stage = Stage::Prepared; emit stopped(attempt, result); return;
        }
        driveStop(); return;
    }
    if (stage == Stage::Preparing) {
        if (operation != Operation::Inspect) return;
        stage = Stage::Prepared; emit prepared(attempt, result); return;
    }
    if (result.succeeded() && helper.state() == HelperState::Active
        && (operation == Operation::Apply || operation == Operation::Extend || operation == Operation::Routes)) {
        const auto configuration = helper.ownedConfiguration();
        const auto device = helper.ownedDevice();
        const auto filter = configuration && device
            ? linuxOriginalNetworkView(*configuration, *device, helper.dnsMode()) : NetworkPolicySession::OriginalViewFilter{};
        if (!filter) { stage = Stage::Prepared; emit lost(attempt, {Status::Failed, QStringLiteral("Cannot identify the active network capture read scope."), true}); return; }
        policy->setOriginalViewFilter(generation, filter);
        policy->setNetworkBusy(generation, false);
    }
    if (operation == Operation::Routes && stage == Stage::Updating) {
        const auto revision = changingPolicy["revision"].toString();
        changingPolicy = {}; nextCapture.clear(); automaticPolicy = false;
        stage = result.succeeded() ? Stage::Ready : Stage::Prepared;
        policy->setNetworkBusy(generation, false);
        if (!result.succeeded()) { emit lost(attempt, result); }
        policy->completePolicy(generation, revision, result.succeeded() ? CoreEngine::RequestStatus::Success : CoreEngine::RequestStatus::Failed);
        return;
    }
    if ((operation == Operation::Extend || operation == Operation::Routes) && stage == Stage::Ready) {
        if (!result.succeeded()) { stage = Stage::Prepared; emit lost(attempt, result); }
        return;
    }
    if (stage == Stage::Activating && operation == Operation::Apply) {
        if (!result.succeeded()) { stage = Stage::Prepared; policy->setNetworkBusy(generation, false); emit ready(attempt, result); return; }
        attaching = true; core->attachTUN(generation, helper.descriptor(), quint32(mtu), true);
    }
}

void LinuxNetworkAccess::observeModel()
{
    if (stage != Stage::Ready || generation != policy->currentGeneration() || automaticPolicy || policy->isBusy()) return;
    if (policy->status() != CoreEngine::RequestStatus::Success) {
        stage = Stage::Prepared; emit lost(attempt, {Status::Failed, QStringLiteral("Cannot completely read the original network (%1); restoring ownership.")
            .arg(policy->failureDetail().isEmpty() ? QStringLiteral("reason unavailable") : policy->failureDetail()), true}); return;
    }
    const auto model = policy->model();
    const auto exit = originalExitSnapshot(model["network"].toObject(), model["resources"].toObject()["underlay_interface"].toString());
    const auto owned = helper.ownedConfiguration();
    if (!exit || *exit != originalExit) {
        stage = Stage::Prepared; emit restartRequired(attempt, QStringLiteral("Original network exit changed; restoring before reconnecting.")); return;
    }
    const auto update = owned ? updatedLinuxCapturePrefixes(model["resources"].toObject(), policy->confirmedProtection(), *owned,
        model["network"].toObject(), model["dns"].toObject()) : std::nullopt;
    if (!update) { stage = Stage::Prepared; emit restartRequired(attempt, QStringLiteral("Original DNS or campus scope changed; restoring before reconnecting.")); return; }
    auto actual = owned->capturePrefixes, expected = *update; actual.sort(); expected.sort();
    if (actual != expected) { helper.reconcile(*update); return; }
    automaticPolicy = true;
    const auto result = policy->synchronizeProtection();
    if (result == CoreEngine::RequestStatus::Pending) return;
    automaticPolicy = false;
    if (result != CoreEngine::RequestStatus::Success) {
        stage = Stage::Prepared; emit restartRequired(attempt, QStringLiteral("Cannot confirm original-network protection; restoring ownership."));
    }
}

void LinuxNetworkAccess::applyPolicy(const QJsonObject &value)
{
    const auto owned = helper.ownedConfiguration();
    const auto model = policy->model();
    const auto update = owned ? updatedLinuxCapturePrefixes(model["resources"].toObject(), value, *owned,
        model["network"].toObject(), model["dns"].toObject()) : std::nullopt;
    if (stage != Stage::Ready || helper.state() != HelperState::Active || !update) {
        const bool automatic = automaticPolicy; automaticPolicy = false;
        policy->completePolicy(value["generation"].toString(), value["revision"].toString(), CoreEngine::RequestStatus::Unavailable);
        if (automatic) { stage = Stage::Prepared; emit restartRequired(attempt, QStringLiteral("Cannot apply updated network protection; restoring before reconnecting.")); }
        return;
    }
    changingPolicy = value; nextCapture = *update; stage = Stage::Updating;
    policy->setNetworkBusy(generation, true); core->updatePolicy(value);
}

void LinuxNetworkAccess::finishPolicy(CoreEngine::RequestStatus status)
{
    const auto revision = changingPolicy["revision"].toString();
    const bool automatic = automaticPolicy;
    changingPolicy = {}; nextCapture.clear(); automaticPolicy = false; stage = Stage::Ready;
    policy->setNetworkBusy(generation, false); policy->completePolicy(generation, revision, status);
    if (automatic && status != CoreEngine::RequestStatus::Success && stage == Stage::Ready) {
        stage = Stage::Prepared; emit restartRequired(attempt, QStringLiteral("Cannot confirm updated network protection; restoring before reconnecting."));
    }
}

void LinuxNetworkAccess::stop(const QUuid &id)
{
    if (id != attempt) { emit stopped(id, {Status::Failed, QStringLiteral("Recovery request does not belong to the current connection."), true}); return; }
    if (stage == Stage::Stopping) return;
    monitor.reset();
    stage = Stage::Stopping; driveStop();
}

void LinuxNetworkAccess::driveStop()
{
    if (stage != Stage::Stopping || preparing) return;
    switch (helper.state()) {
    case HelperState::Idle:
        if (helper.restorationPending()) {
            emit quiesced(attempt);
            helper.inspect(attempt);
            return;
        }
        lock.reset(); stage = Stage::Idle; generation.clear(); changingPolicy = {}; nextCapture.clear(); originalExit = {};
        attaching = automaticPolicy = false;
        emit stopped(attempt, {}); return;
    case HelperState::Active: helper.restore(); return;
    default: helper.cancel(); return;
    }
}
