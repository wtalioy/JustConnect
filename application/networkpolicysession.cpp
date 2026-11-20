#include "networkpolicysession.h"
#include "networkprotection.h"
#include <QtConcurrent>
#include <QHostAddress>
#include <limits>

using Status = CoreEngine::RequestStatus;

NetworkPolicySession::NetworkPolicySession(CoreEngine *engine, DnsReader reader, QObject *parent,
    std::function<bool()> captureRequired)
    : QObject(parent), engine(engine), reader(std::move(reader))
{
    connect(engine, &CoreEngine::sessionStarted, this, [this, required = std::move(captureRequired)](const QString &id) {
        begin(id, required && !required());
    });
    connect(engine, &CoreEngine::initialProtectionApplied, this, [this](const QJsonObject &policy) {
        if (generation.isEmpty() || policy["generation"] != generation || !confirmedPolicy.isEmpty() || isPolicyUpdating()
            || policy["schema_version"].toInteger() <= 0 || policy["revision"] != "0"
            || !policy["protected"].isArray() || !policy["protected_names"].isArray()
            || !policy["campus"].isArray() || !policy["campus"].toArray().isEmpty()
            || !policy["campus_names"].isArray() || !policy["campus_names"].toArray().isEmpty()) return;
        confirmedPolicy = policy;
        emit changed();
    });
    connect(engine, &CoreEngine::finished, this, &NetworkPolicySession::clear);
    connect(engine, &QObject::destroyed, this, &NetworkPolicySession::clear);
    connect(engine, &CoreEngine::connectionEstablished, this, [this] {
        if (generation.isEmpty() || transportReady) return;
        transportReady = true;
        resourcesPending = true;
        this->engine->readSnapshot(CoreEngine::Snapshot::Resources, generation);
    });
    connect(engine, &CoreEngine::snapshotReady, this,
        [this](CoreEngine::Snapshot kind, const QString &id, const QJsonObject &data, Status status) {
            if (kind == CoreEngine::Snapshot::Coexistence) return;
            if (generation.isEmpty() || id != generation) return;
            const bool isNetwork = kind == CoreEngine::Snapshot::Network;
            auto &pending = isNetwork ? networkPending : resourcesPending;
            if (!pending) return;
            pending = false;
            auto &resultStatus = isNetwork ? networkStatus : resourceStatus;
            auto &result = isNetwork ? network : resources;
            resultStatus = status;
            result = {};
            if (status == Status::Success) {
                const auto value = data.value(isNetwork ? "network" : "resources");
                if (!value.isObject()) resultStatus = Status::Failed;
                else {
                    result = value.toObject();
                    if (isNetwork) networkVersion = data["schema_version"];
                }
            }
            if (localProxy) emit changed();
            else publish();
        });
    connect(engine, &CoreEngine::policyUpdated, this,
        [this](const QString &id, const QString &appliedRevision, Status status) {
            if (!policyApplier) completePolicy(id,appliedRevision,status);
        });
    connect(&watcher, &QFutureWatcher<ModelResult>::finished, this, [this] {
        const auto result = watcher.result();
        workerBusy = false;
        if (!generation.isEmpty() && result.serial == serial) {
            modelStatus = result.status;
            modelFailureReason = result.status == Status::Success ? QString() : result.reason;
            if (result.status == Status::Success) lastModel = result.model;
        }
        publish();
    });
}

NetworkPolicySession::~NetworkPolicySession()
{
    watcher.waitForFinished();
}

void NetworkPolicySession::begin(const QString &id, bool proxyOnly)
{
    clear();
    if (id.isEmpty()) return;
    generation = id;
    localProxy = proxyOnly;
    if (!localProxy) refresh();
}

void NetworkPolicySession::clear()
{
    ++serial;
    generation.clear();
    localProxy = false;
    resourceStatus = Status::Pending;
    transportReady = networkPending = resourcesPending = networkBusy = refreshQueued = false;
    originalViewFilter = {};
    policyApplier = {};
    waitingForPolicyModel = false;
    network = resources = lastModel = {};
    networkVersion = {};
    confirmedPolicy = pendingPolicy = {};
    revision = 0;
    lastPolicyStatus.reset();
    currentStatus = Status::Stale;
    emit changed();
}

void NetworkPolicySession::setNetworkBusy(const QString &id, bool busy)
{
    if (id.isEmpty() || id != generation || networkBusy == busy) return;
    networkBusy = busy;
    publish();
}

void NetworkPolicySession::setOriginalViewFilter(const QString &id, OriginalViewFilter filter)
{
    if (id.isEmpty() || id != generation) return;
    originalViewFilter = std::move(filter);
    ++serial;
    currentStatus = modelStatus = Status::Pending;
    refreshQueued = true;
    publish();
}

void NetworkPolicySession::setPolicyApplier(const QString &id, PolicyApplier applier)
{
    if (!generation.isEmpty() && id == generation && !isPolicyUpdating()) policyApplier = std::move(applier);
}

void NetworkPolicySession::completePolicy(const QString &id, const QString &appliedRevision, Status status)
{
    if (!isPolicyUpdating() || id != generation || appliedRevision != pendingPolicy["revision"].toString()) return;
    if (status == Status::Success) confirmedPolicy = pendingPolicy;
    waitingForPolicyModel = false;
    pendingPolicy = {};
    lastPolicyStatus = status;
    publish();
}

bool NetworkPolicySession::refresh()
{
    if (localProxy || !engine || generation.isEmpty() || networkBusy || networkPending || resourcesPending || (isPolicyUpdating() && !waitingForPolicyModel)
        || (workerBusy && workerSerial == serial)) return false;
    refreshQueued = false;
    ++serial;
    network = resources = {};
    networkVersion = {};
    modelFailureReason.clear();
    networkStatus = resourceStatus = modelStatus = Status::Pending;
    networkPending = true;
    currentStatus = Status::Pending;
    engine->readSnapshot(CoreEngine::Snapshot::Network, generation);
    if (transportReady) {
        resourcesPending = true;
        engine->readSnapshot(CoreEngine::Snapshot::Resources, generation);
    }
    publish();
    return true;
}

void NetworkPolicySession::requestRefresh()
{
    if (localProxy || !engine || generation.isEmpty()) return;
    // A change observed while a refresh (or a native policy write) runs must
    // not be lost, but it must not multiply either: one queued follow-up
    // coalesces every observation made while this one is outstanding, and
    // publish() drains it once the busy flags clear. An explicit refresh()
    // from the retry path keeps its immediate, refusing semantics.
    if (isBusy()) {
        refreshQueued = true;
        return;
    }
    refresh();
}

CoreEngine::RequestStatus NetworkPolicySession::synchronizeProtection()
{
    if (!engine || generation.isEmpty() || isBusy() || currentStatus != Status::Success
        || networkVersion.toInteger() <= 0 || confirmedPolicy.isEmpty()) return Status::Unavailable;
    auto policy = protectionConfiguration(lastModel["targets"].toArray(),lastModel["name_targets"].toArray());
    policy["campus"] = campusAddresses();
    policy["campus_names"] = campusNames();
    if (policy["protected"] == confirmedPolicy["protected"] && policy["protected_names"] == confirmedPolicy["protected_names"])
        return Status::Success;
    policy["generation"] = generation;
    policy["schema_version"] = networkVersion;
    if (!submitPolicy(policy)) return lastPolicyStatus.value_or(Status::Failed);
    return isPolicyUpdating() ? Status::Pending : lastPolicyStatus.value_or(Status::Failed);
}

bool NetworkPolicySession::setCampusAddress(const QString &text, bool campus)
{
    if (!engine || generation.isEmpty() || networkBusy || isPolicyUpdating()) return false;
    auto choices = campusAddresses();
    const bool owned = choices.contains(text);
    if ((currentStatus != Status::Success || isBusy()) && (campus || !owned)) return false;
    const QHostAddress address(text);
    if (address.protocol() != QAbstractSocket::IPv4Protocol || address.toString() != text) {
        lastPolicyStatus = Status::Invalid;
        emit changed();
        return false;
    }
    QJsonObject policy;
    if (currentStatus == Status::Success && networkVersion.toInteger() > 0) {
        bool protectedAddress = false;
        for (const auto &value : lastModel["targets"].toArray()) {
            const auto prefix = value.toObject()["prefix"].toString();
            protectedAddress |= address.isInSubnet(QHostAddress::parseSubnet(prefix));
        }
        if (!protectedAddress && (campus || !owned)) {
            lastPolicyStatus = Status::Invalid;
            emit changed();
            return false;
        }
        policy = protectionConfiguration(lastModel["targets"].toArray(), lastModel["name_targets"].toArray());
        policy["schema_version"] = networkVersion;
        policy["generation"] = generation;
        if (confirmedPolicy.contains("protected_names")) {
            policy["protected_names"] = confirmedPolicy["protected_names"];
            policy["campus_names"] = confirmedPolicy["campus_names"];
        }
    } else if (!campus && owned) policy = confirmedPolicy;
    else {
        lastPolicyStatus = Status::Unavailable;
        emit changed();
        return false;
    }
    if (owned == campus) {
        lastPolicyStatus = Status::Success;
        emit changed();
        return true;
    }
    if (campus) choices.append(text);
    else for (int i = choices.size() - 1; i >= 0; --i)
        if (choices[i] == text) choices.removeAt(i);
    policy["campus"] = choices;
    return submitPolicy(policy);
}

bool NetworkPolicySession::setCampusName(const QString &text, bool campus)
{
    if (!engine || generation.isEmpty() || networkBusy || isPolicyUpdating()) return false;
    const auto name = canonicalProtectionName(text);
    if (!name) {
        lastPolicyStatus = Status::Invalid;
        emit changed();
        return false;
    }
    auto choices = campusNames();
    const bool owned = choices.contains(*name);
    if ((currentStatus != Status::Success || isBusy()) && (campus || !owned)) return false;
    auto policy = confirmedPolicy;
    if (policy.isEmpty()) {
        if (currentStatus != Status::Success || networkVersion.toInteger() <= 0) {
            lastPolicyStatus = Status::Unavailable;
            emit changed();
            return false;
        }
        policy = protectionConfiguration(lastModel["targets"].toArray(), lastModel["name_targets"].toArray());
        policy["schema_version"] = networkVersion;
        policy["generation"] = generation;
    }
    if (owned == campus) {
        lastPolicyStatus = Status::Success;
        emit changed();
        return true;
    }
    if (campus) choices.append(*name);
    else for (int i = choices.size() - 1; i >= 0; --i)
        if (choices[i] == *name) choices.removeAt(i);
    policy["campus_names"] = choices;
    return submitPolicy(policy);
}

bool NetworkPolicySession::submitPolicy(QJsonObject policy)
{
    if (revision == std::numeric_limits<quint64>::max()) {
        lastPolicyStatus = Status::Limit;
        emit changed();
        return false;
    }
    policy["revision"] = QString::number(++revision);
    pendingPolicy = policy;
    lastPolicyStatus = Status::Pending;
    // An owned choice can be withdrawn while its platform view is being refreshed.
    waitingForPolicyModel = policyApplier && currentStatus == Status::Pending;
    if (!waitingForPolicyModel) {
        if (policyApplier) policyApplier(policy);
        else engine->updatePolicy(policy);
    }
    publish();
    return true;
}

void NetworkPolicySession::buildModel()
{
    if (!reader) { modelStatus = Status::Unavailable; return; }
    workerBusy = true;
    const auto request = workerSerial = serial;
    const auto read = reader;
    watcher.setFuture(QtConcurrent::run([read, request, id=generation, version=networkVersion, original=network,
                                        campus=resources, filter=originalViewFilter, previous=lastModel] {
        QString reason;
        try {
            const auto snapshot = read();
            using NativeStatus = PlatformOperationResult::Status;
            if (!snapshot.result.succeeded()) {
                const auto status = snapshot.result.status == NativeStatus::Unsupported ? Status::Unavailable
                    : snapshot.result.status == NativeStatus::Cancelled ? Status::Stale : Status::Failed;
                return ModelResult{request, status, {}, QStringLiteral("system resolver snapshot read failed: %1")
                    .arg(snapshot.result.detail.isEmpty() ? QStringLiteral("unspecified") : snapshot.result.detail)};
            }
            if (filter) {
                reason = QStringLiteral("the owned network view filter rejected the snapshot");
                const auto view = filter(original, snapshot.data, &reason);
                if (!view) return ModelResult{request, Status::Failed, {}, reason};
                return finishModel(request, id, version, campus, previous, *view);
            }
            return finishModel(request, id, version, campus, previous, OriginalView{original, snapshot.data});
        } catch (...) { return ModelResult{request, Status::Failed, {}, QStringLiteral("the model worker crashed")}; }
    }));
}

NetworkPolicySession::ModelResult NetworkPolicySession::finishModel(quint64 request, const QString &id,
    const QJsonValue &version, const QJsonObject &campus, const QJsonObject &previous, const OriginalView &view)
{
    const auto projected = originalProxyNetworkView(view.first);
    if (!projected) return {request, Status::Failed, {}, QStringLiteral("cannot project the proxy network view")};
    // Reuse only after a fresh, successful read and projection of the active ownership view.
    if (!previous.isEmpty() && previous["schema_version"] == version && previous["network"] == *projected
        && previous["resources"] == campus && previous["dns"] == view.second)
        return {request, Status::Success, previous, {}};
    const auto targets = originalNetworkProtection(*projected);
    if (!targets) return {request, Status::Failed, {}, QStringLiteral("cannot derive protected targets from the network view")};
    const auto conflicts = campusProtectionConflicts(*targets, campus);
    if (!conflicts) return {request, Status::Failed, {}, QStringLiteral("the campus resources shape is invalid for protection")};
    const auto names = originalDnsProtection(view.second);
    if (!names) return {request, Status::Failed, {}, QStringLiteral("cannot derive DNS protection from the resolver snapshot")};
    return {request, Status::Success,
        {{"schema_version", version}, {"generation", id}, {"network", *projected}, {"resources", campus},
         {"dns", view.second}, {"dns_namespaces", (*names)["namespaces"]}, {"name_targets", (*names)["targets"]},
         {"targets", *targets}, {"conflicts", *conflicts}}, {}};
}

QString NetworkPolicySession::failureDetail() const
{
    if (networkStatus != Status::Success) return QStringLiteral("original network snapshot read failed");
    if (resourceStatus != Status::Success) return QStringLiteral("campus resources snapshot read failed");
    if (modelStatus != Status::Success && modelStatus != Status::Pending)
        return QStringLiteral("original network model build failed: %1")
            .arg(modelFailureReason.isEmpty() ? QStringLiteral("unspecified") : modelFailureReason);
    return {};
}

void NetworkPolicySession::publish()
{
    if (generation.isEmpty() || localProxy) { emit changed(); return; }
    if (refreshQueued && !networkBusy && !workerBusy && !networkPending && !resourcesPending && (!isPolicyUpdating() || waitingForPolicyModel)) {
        refreshQueued = false;
        refresh();
        return;
    }
    if (!networkBusy && !refreshQueued && networkStatus == Status::Success && resourceStatus == Status::Success
        && modelStatus == Status::Pending && !workerBusy) buildModel();
    currentStatus = Status::Success;
    for (const auto value : {networkStatus, resourceStatus, modelStatus}) {
        if (value != Status::Success) {
            currentStatus = value;
            break;
        }
    }
    if (waitingForPolicyModel && !networkBusy && !workerBusy && !networkPending && !resourcesPending
        && currentStatus != Status::Pending) {
        const auto value = pendingPolicy;
        waitingForPolicyModel = false;
        if (currentStatus == Status::Success && policyApplier) policyApplier(value);
        else completePolicy(generation,value["revision"].toString(),Status::Unavailable);
    }
    emit changed();
}
