#include "networkpolicysession.h"
#include "networkprotection.h"
#include <QtConcurrent>
#include <QHostAddress>
#include <limits>

using Status = CoreEngine::RequestStatus;

NetworkPolicySession::NetworkPolicySession(CoreEngine *engine, DnsReader reader, QObject *parent)
    : QObject(parent), engine(engine), reader(std::move(reader))
{
    connect(engine, &CoreEngine::sessionStarted, this, &NetworkPolicySession::begin);
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
            publish();
        });
    connect(engine, &CoreEngine::policyUpdated, this,
        [this](const QString &id, const QString &appliedRevision, Status status) {
            if (!isPolicyUpdating() || id != generation || appliedRevision != pendingPolicy["revision"].toString()) return;
            if (status == Status::Success) confirmedPolicy = pendingPolicy;
            pendingPolicy = {};
            lastPolicyStatus = status;
            emit changed();
        });
    connect(&watcher, &QFutureWatcher<ModelResult>::finished, this, [this] {
        const auto result = watcher.result();
        workerBusy = false;
        if (!generation.isEmpty() && result.serial == serial) {
            modelStatus = result.status;
            currentModel = result.status == Status::Success ? result.model : QJsonObject{};
        }
        publish();
    });
}

NetworkPolicySession::~NetworkPolicySession()
{
    watcher.waitForFinished();
}

void NetworkPolicySession::begin(const QString &id)
{
    clear();
    if (id.isEmpty()) return;
    generation = id;
    refresh();
}

void NetworkPolicySession::clear()
{
    ++serial;
    generation.clear();
    transportReady = networkPending = resourcesPending = false;
    network = resources = currentModel = {};
    networkVersion = {};
    confirmedPolicy = pendingPolicy = {};
    revision = 0;
    lastPolicyStatus.reset();
    currentStatus = Status::Stale;
    emit changed();
}

bool NetworkPolicySession::refresh()
{
    if (!engine || generation.isEmpty() || networkPending || resourcesPending || isPolicyUpdating()
        || (workerBusy && workerSerial == serial)) return false;
    ++serial;
    network = resources = currentModel = {};
    networkVersion = {};
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

bool NetworkPolicySession::setCampusAddress(const QString &text, bool campus)
{
    if (!engine || generation.isEmpty() || isPolicyUpdating()) return false;
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
        for (const auto &value : currentModel["targets"].toArray()) {
            const auto prefix = value.toObject()["prefix"].toString();
            protectedAddress |= address.isInSubnet(QHostAddress::parseSubnet(prefix));
        }
        if (!protectedAddress && (campus || !owned)) {
            lastPolicyStatus = Status::Invalid;
            emit changed();
            return false;
        }
        policy = protectionConfiguration(currentModel["targets"].toArray(), currentModel["name_targets"].toArray());
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
    if (!engine || generation.isEmpty() || isPolicyUpdating()) return false;
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
        policy = protectionConfiguration(currentModel["targets"].toArray(), currentModel["name_targets"].toArray());
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
    engine->updatePolicy(policy);
    emit changed();
    return true;
}

void NetworkPolicySession::buildModel()
{
    if (!reader) { modelStatus = Status::Unavailable; return; }
    workerBusy = true;
    const auto request = workerSerial = serial;
    const auto read = reader;
    watcher.setFuture(QtConcurrent::run([read, request, id=generation, version=networkVersion, original=network, campus=resources] {
        try {
            const auto snapshot = read();
            using NativeStatus = PlatformOperationResult::Status;
            if (!snapshot.result.succeeded()) {
                const auto status = snapshot.result.status == NativeStatus::Unsupported ? Status::Unavailable
                    : snapshot.result.status == NativeStatus::Cancelled ? Status::Stale : Status::Failed;
                return ModelResult{request, status, {}};
            }
            const auto targets = originalNetworkProtection(original);
            const auto conflicts = targets ? campusProtectionConflicts(*targets, campus) : std::nullopt;
            const auto names = originalDnsProtection(snapshot.data);
            if (!targets || !conflicts || !names) return ModelResult{request, Status::Failed, {}};
            return ModelResult{request, Status::Success,
                {{"schema_version", version}, {"generation", id}, {"network", original}, {"resources", campus},
                 {"dns", snapshot.data}, {"dns_namespaces", (*names)["namespaces"]}, {"name_targets", (*names)["targets"]},
                 {"targets", *targets}, {"conflicts", *conflicts}}};
        } catch (...) { return ModelResult{request, Status::Failed, {}}; }
    }));
}

void NetworkPolicySession::publish()
{
    if (generation.isEmpty()) { emit changed(); return; }
    if (networkStatus == Status::Success && resourceStatus == Status::Success
        && modelStatus == Status::Pending && !workerBusy) buildModel();
    currentStatus = Status::Success;
    for (const auto value : {networkStatus, resourceStatus, modelStatus}) {
        if (value != Status::Success) {
            currentStatus = value;
            break;
        }
    }
    if (currentStatus != Status::Success) currentModel = {};
    emit changed();
}
