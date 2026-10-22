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
            if (!policyBusy || id != generation || appliedRevision != pendingRevision) return;
            if (status == Status::Success) chosenCampus = pendingCampus;
            pendingCampus = {};
            pendingRevision.clear();
            policyBusy = false;
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
    chosenCampus = pendingCampus = {};
    pendingRevision.clear();
    revision = 0;
    policyBusy = false;
    lastPolicyStatus = Status::Unavailable;
    currentStatus = Status::Stale;
    emit changed();
}

bool NetworkPolicySession::refresh()
{
    if (!engine || generation.isEmpty() || networkPending || resourcesPending || policyBusy
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
    if (!engine || generation.isEmpty() || currentStatus != Status::Success || isBusy()) return false;
    const QHostAddress address(text);
    QJsonArray prefixes;
    bool protectedAddress = false;
    for (const auto &value : currentModel["targets"].toArray()) {
        const auto prefix = value.toObject()["prefix"].toString();
        prefixes.append(prefix);
        protectedAddress |= address.isInSubnet(QHostAddress::parseSubnet(prefix));
    }
    if (address.protocol() != QAbstractSocket::IPv4Protocol || address.toString() != text
        || (!protectedAddress && (campus || !chosenCampus.contains(text)))) {
        lastPolicyStatus = Status::Invalid;
        emit changed();
        return false;
    }
    if (networkVersion.toInteger() <= 0) {
        lastPolicyStatus = Status::Unavailable;
        emit changed();
        return false;
    }
    pendingCampus = chosenCampus;
    const auto found = pendingCampus.contains(text);
    if (found == campus) {
        lastPolicyStatus = Status::Success;
        emit changed();
        return true;
    }
    if (revision == std::numeric_limits<quint64>::max()) {
        lastPolicyStatus = Status::Limit;
        emit changed();
        return false;
    }
    if (campus) pendingCampus.append(text);
    else for (int i = pendingCampus.size() - 1; i >= 0; --i)
        if (pendingCampus[i] == text) pendingCampus.removeAt(i);
    pendingRevision = QString::number(++revision);
    policyBusy = true;
    lastPolicyStatus = Status::Pending;
    const QJsonObject policy{{"schema_version", networkVersion}, {"generation", generation}, {"revision", pendingRevision},
                             {"protected", prefixes}, {"campus", pendingCampus}};
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
            const auto namespaces = originalDnsNamespaces(snapshot.data);
            if (!targets || !conflicts || !namespaces) return ModelResult{request, Status::Failed, {}};
            return ModelResult{request, Status::Success,
                {{"schema_version", version}, {"generation", id}, {"network", original}, {"resources", campus},
                 {"dns", snapshot.data}, {"dns_namespaces", *namespaces}, {"targets", *targets}, {"conflicts", *conflicts}}};
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
