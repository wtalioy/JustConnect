#include "embeddedcoreengine.h"
#include "justconnect.h"
#include "application/networkprotection.h"
#include "infrastructure/dns/dnssnapshot.h"
#include <atomic>
#include <memory>
#ifdef Q_OS_WIN
#include <windows.h>
#include <QHostAddress>
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
#include <fcntl.h>
#include <unistd.h>
#endif

#include <QCoreApplication>
#include <QJsonDocument>
#include <QLibrary>
#include <QTimer>

namespace {
#define CORE_FUNCTIONS(X) X(jc_abi_version) X(jc_build_info) X(jc_config_validate) X(jc_session_create) X(jc_session_start) \
    X(jc_session_read) X(jc_session_respond) X(jc_session_stop) X(jc_session_destroy)
#define CORE_EXTENSIONS(X) X(jc_session_update_policy) X(jc_network_snapshot) X(jc_session_resources) X(jc_session_attach_tun) X(jc_session_attach_tun_dns) X(jc_session_attach_windows_pipe) X(jc_session_ack_dns_routes)
struct Library {
#define MEMBER(name) decltype(&::name) name = nullptr;
    CORE_FUNCTIONS(MEMBER)
    CORE_EXTENSIONS(MEMBER)
#undef MEMBER
    QLibrary library;
    bool available = false;
    Library() {
#ifdef JC_SHARED_LIBRARY
        library.setFileName(QCoreApplication::applicationDirPath() + "/" + QStringLiteral(JC_SHARED_LIBRARY));
        library.setLoadHints(QLibrary::PreventUnloadHint);
        if (!library.load()) return;
#define LOAD(name) name = reinterpret_cast<decltype(name)>(library.resolve(#name)); if (!name) return;
#else
#define LOAD(name) name = &::name;
#endif
        CORE_FUNCTIONS(LOAD)
#undef LOAD
#ifdef JC_SHARED_LIBRARY
#define LOAD_OPTIONAL(name) name = reinterpret_cast<decltype(name)>(library.resolve(#name));
#else
#define LOAD_OPTIONAL(name) name = &::name;
#endif
        CORE_EXTENSIONS(LOAD_OPTIONAL)
#undef LOAD_OPTIONAL
        available = jc_abi_version() == JC_ABI_VERSION;
    }
};
Library &library() {
    static Library instance; // Go runtime stays loaded until process exit.
    return instance;
}
QJsonObject configuration(const ConnectionProfile &p, CoreEngine::Operation operation) {
    QJsonObject config{{"schema_version", int(JC_ABI_VERSION)},
        {"operation", operation == CoreEngine::Operation::AuthMethods ? "auth_methods" : "connect"},
        {"tls",QJsonObject{{"skip_verify",!p.tls.verify},{"ca_pem",p.tls.caPem},{"allow_unverified_nodes",p.tls.allowUnverifiedNodes}}},
        {"server", QJsonObject{{"host", p.endpoint.server}, {"port", p.endpoint.port}}},
        {"auth", QJsonObject{{"auth_id",p.endpoint.authId},{"sub_type",p.endpoint.authSubType},{"method", p.endpoint.authType.isEmpty() ? QString() : "auth/" + p.endpoint.authType},
            {"username", p.credentials.username}, {"password", p.credentials.password},
            {"phone", p.endpoint.phone}, {"domain", p.endpoint.loginDomain}, {"totp_secret", p.credentials.totpSecret}}},
        {"listeners", QJsonObject{{"socks", p.proxy.socksBind}, {"http", p.proxy.httpBind}}},
        {"network", QJsonObject{{"interface", p.behavior.bindInterface}, {"auto_detect", p.behavior.autoDetectInterface},
            {"local_dns", p.dns.localDnsServer}, {"secondary_dns", p.dns.secondary},
            {"dns_cache_ttl", p.dns.ttl}, {"disable_remote_dns", p.dns.disableRemoteDns}}}};
    if (operation==CoreEngine::Operation::Connect)
        config["keepalive"]=QJsonObject{{"mode",p.keepAlive.mode},{"url",p.keepAlive.url}};
    if (operation==CoreEngine::Operation::Connect && p.behavior.rememberAuthentication) {
        QJsonObject cache{{"enabled",true}};
        if (!p.authenticationCache.data.isEmpty() || !p.authenticationCache.account.isEmpty()) {
            cache["account"]=p.authenticationCache.account;
            cache["data"]=QString::fromLatin1(p.authenticationCache.data.toBase64());
        }
        config["authentication_cache"]=cache;
    }
    return config;
}
QByteArray configurationBytes(const ConnectionProfile &profile, CoreEngine::Operation operation) {
    auto config = QJsonDocument(configuration(profile, operation)).toJson(QJsonDocument::Compact);
    if (config.size() > JC_MAX_INPUT) config.clear();
    return config;
}
ConnectionError connectionError(int status) {
    if (status == JC_OK || status == JC_CANCELLED) return ConnectionError::NONE;
    if (status == JC_TLS_TRUST) return ConnectionError::TLS_TRUST;
    if (status == JC_TLS_PROTOCOL) return ConnectionError::TLS_PROTOCOL;
    if (status == JC_NETWORK_FAILURE) return ConnectionError::NETWORK_FAILED;
    if (status == JC_TIMEOUT) return ConnectionError::TIMED_OUT;
    if (status == JC_AUTH_UNSUPPORTED) return ConnectionError::AUTHENTICATION_UNSUPPORTED;
    if (status == JC_PERMISSION_DENIED) return ConnectionError::PERMISSION_DENIED;
    if (status == JC_SESSION_INVALID) return ConnectionError::SESSION_INVALID;
    if (status == JC_CREDENTIALS_REQUIRED) return ConnectionError::CREDENTIALS_REQUIRED;
    if (status == JC_AUTH_METHOD_CHANGED) return ConnectionError::AUTHENTICATION_CHANGED;
    if (status == JC_INVALID_ARGUMENT) return ConnectionError::INVALID_CONFIGURATION;
    if (status == JC_UNSUPPORTED || status == JC_ABI_MISMATCH) return ConnectionError::CORE_UNAVAILABLE;
    return ConnectionError::CLIENT_FAILED;
}
CoreEngine::RequestStatus requestStatus(int status) {
    switch (status) {
    case JC_OK: return CoreEngine::RequestStatus::Success;
    case JC_BUSY: return CoreEngine::RequestStatus::Pending;
    case JC_STALE_REQUEST: return CoreEngine::RequestStatus::Stale;
    case JC_INVALID_ARGUMENT: return CoreEngine::RequestStatus::Invalid;
    case JC_LIMIT: return CoreEngine::RequestStatus::Limit;
    case JC_UNSUPPORTED: case JC_ABI_MISMATCH: return CoreEngine::RequestStatus::Unavailable;
    default: return CoreEngine::RequestStatus::Failed;
    }
}
struct NativeSnapshot {
    int status = JC_UNSUPPORTED;
    QJsonObject data;
};
NativeSnapshot readNativeSnapshot(CoreEngine::Snapshot kind, uint64_t handle = 0, uint64_t generation = 0) {
    auto &api = library();
    const bool resources = kind == CoreEngine::Snapshot::Resources;
    const auto capabilities = EmbeddedCoreEngine::buildInfo()["capabilities"].toObject();
    if (!(resources ? api.jc_session_resources && capabilities["resource_snapshot"].toBool()
                    : api.jc_network_snapshot && capabilities["network_snapshot"].toBool())) return {};
    QByteArray bytes(JC_MAX_OUTPUT, Qt::Uninitialized);
    uint32_t length = 0;
    const int status = resources
        ? api.jc_session_resources(handle, generation, reinterpret_cast<uint8_t *>(bytes.data()), uint32_t(bytes.size()), &length)
        : api.jc_network_snapshot(JC_ABI_VERSION, reinterpret_cast<uint8_t *>(bytes.data()), uint32_t(bytes.size()), &length);
    if (status != JC_OK) return {status, {}};
    QJsonParseError error{};
    const auto doc = length <= uint32_t(bytes.size()) ? QJsonDocument::fromJson(bytes.first(length), &error) : QJsonDocument();
    const auto snapshot = doc.object();
    if (error.error != QJsonParseError::NoError || !doc.isObject() || snapshot["schema_version"].toInt() != JC_ABI_VERSION
        || !snapshot[resources ? "resources" : "network"].isObject()
        || (resources && snapshot["generation"].toString() != QString::number(generation))) return {JC_INTERNAL, {}};
    return {JC_OK, snapshot};
}
int installInitialProtection(QByteArray &config, QJsonObject &initialPolicy) {
    auto fields = QJsonDocument::fromJson(config).object();
    if (fields["operation"] != "connect") return JC_OK;
    const auto capabilities = EmbeddedCoreEngine::buildInfo()["capabilities"].toObject();
    if (!capabilities["initial_protection"].toBool() || !capabilities["name_protection"].toBool()) return JC_UNSUPPORTED;
    const auto snapshot = readNativeSnapshot(CoreEngine::Snapshot::Network);
    if (snapshot.status != JC_OK) return snapshot.status;
    const auto targets = originalNetworkProtection(snapshot.data["network"].toObject());
    if (!targets) return JC_INTERNAL;
    const auto dns = readSystemDnsSnapshot();
    if (!dns.result.succeeded()) {
        using Status = PlatformOperationResult::Status;
        switch (dns.result.status) {
        case Status::TimedOut: return JC_TIMEOUT;
        case Status::PermissionDenied: return JC_PERMISSION_DENIED;
        case Status::Unsupported: return JC_UNSUPPORTED;
        case Status::Cancelled: return JC_CANCELLED;
        default: return JC_INTERNAL;
        }
    }
    const auto names = originalDnsProtection(dns.data);
    if (!names) return JC_UNSUPPORTED;
    const auto protection = protectionConfiguration(*targets, (*names)["targets"].toArray());
    fields["protection"] = protection;
    initialPolicy = protection;
    initialPolicy["schema_version"] = snapshot.data["schema_version"];
    config.fill('\0');
    config = QJsonDocument(fields).toJson(QJsonDocument::Compact);
    return config.size() > JC_MAX_INPUT ? JC_LIMIT : JC_OK;
}
}

class CoreEventPump : public QObject
{
    Q_OBJECT
public:
    uint64_t handle = 0;
    uint64_t generation = 0;
    quint64 serial = 0;
    bool active = false;
    QJsonObject initialPolicy;
    std::atomic_bool cancelled{false};
    ~CoreEventPump() override {
        if (!handle) return;
        // No ABI call or borrowed buffer may outlive this worker.
        while (library().jc_session_destroy(handle, JC_MAX_WAIT_MS) == JC_TIMEOUT) {}
    }
    void start(quint64 nextSerial, QByteArray config) {
        serial = nextSerial;
        initialPolicy = {};
        auto &api = library();
        int status = JC_UNSUPPORTED;
        if (api.available) {
            status = api.jc_config_validate(JC_ABI_VERSION, reinterpret_cast<const uint8_t *>(config.constData()), uint32_t(config.size()));
            if (status == JC_OK && !cancelled.load() && !QThread::currentThread()->isInterruptionRequested())
                status = installInitialProtection(config, initialPolicy);
            // Stop can arrive while the native read is blocking this worker's event loop.
            if (cancelled.load() || QThread::currentThread()->isInterruptionRequested()) status = JC_CANCELLED;
            if (status == JC_OK) {
                status = handle ? JC_OK : api.jc_session_create(JC_ABI_VERSION, &handle);
                if (status == JC_OK)
                    status = api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.constData()),
                        uint32_t(config.size()), &generation);
            }
        }
        config.fill('\0');
        if (status != JC_OK) { initialPolicy = {}; emit failed(serial, status); return; }
        if (!initialPolicy.isEmpty()) {
            initialPolicy["generation"] = QString::number(generation);
            initialPolicy["revision"] = "0";
        }
        active = true;
        poll();
    }
    void stop() {
        if (active) library().jc_session_stop(handle, 0);
    }
    void respond(QByteArray response) {
        const auto status = library().jc_session_respond(handle,
            reinterpret_cast<const uint8_t *>(response.constData()), uint32_t(response.size()));
        response.fill('\0');
        if (status == JC_OK) emit accepted(serial);
        else emit rejected(serial);
    }
    void updatePolicy(quint64 id, QByteArray bytes, QString requestedGeneration, QString revision) {
        int status = JC_STALE_REQUEST;
        uint64_t applied = 0;
        if (id == serial && active) {
            auto &api = library();
            status = JC_UNSUPPORTED;
            const auto capabilities = EmbeddedCoreEngine::buildInfo()["capabilities"].toObject();
            if (api.jc_session_update_policy && capabilities["policy_update"].toBool() && capabilities["name_protection"].toBool()) {
                status = api.jc_session_update_policy(handle, reinterpret_cast<const uint8_t *>(bytes.constData()), uint32_t(bytes.size()), &applied);
                bool valid = false;
                const auto requested = requestedGeneration.toULongLong(&valid);
                if (status == JC_OK && (!valid || applied != requested)) status = JC_INTERNAL;
            }
        }
        bytes.fill('\0');
        emit policyResult(id, status == JC_OK ? QString::number(applied) : requestedGeneration, revision, status);
    }
    void readSnapshot(quint64 id, CoreEngine::Snapshot kind, const QString &requestedGeneration) {
        int status = JC_STALE_REQUEST;
        QJsonObject snapshot;
        if (id == serial && active && requestedGeneration == QString::number(generation)) {
            const auto result = readNativeSnapshot(kind, handle, generation);
            status = result.status;
            snapshot = result.data;
        }
        emit snapshotResult(id, kind, requestedGeneration, snapshot, status);
    }
    void attachTUN(quint64 id, const QString &requestedGeneration, int descriptor, quint32 mtu, bool publishDNSRoutes) {
        int status = JC_STALE_REQUEST;
        if (id == serial && active && !cancelled.load() && !QThread::currentThread()->isInterruptionRequested()) {
            bool valid = false;
            const auto requested = requestedGeneration.toULongLong(&valid);
            status = valid && requested && requestedGeneration == QString::number(requested)
                ? (publishDNSRoutes ? library().jc_session_attach_tun_dns : library().jc_session_attach_tun)(handle, requested, descriptor, mtu) : JC_INVALID_ARGUMENT;
        }
        emit tunResult(id, requestedGeneration, status);
    }
    void attachWindowsPipe(quint64 id, const QString &requestedGeneration, quint64 pipe, quint32 helperPID,
        quint32 mtu, quint32 source, quint32 peer, bool publishDNSRoutes) {
        int status = JC_STALE_REQUEST;
        if (id == serial && active && !cancelled.load() && !QThread::currentThread()->isInterruptionRequested()) {
            bool valid = false;
            const auto requested = requestedGeneration.toULongLong(&valid);
            status = valid && requested && requestedGeneration == QString::number(requested)
                ? library().jc_session_attach_windows_pipe(handle, requested, pipe, helperPID, mtu, source, peer, publishDNSRoutes ? 1 : 0)
                : JC_INVALID_ARGUMENT;
        }
        emit tunResult(id, requestedGeneration, status);
    }
    void acknowledgeDNSRoutes(quint64 id, const QString &requestedGeneration, const QString &request, bool applied) {
        int status = JC_STALE_REQUEST;
        if (id == serial && active && !cancelled.load() && requestedGeneration == QString::number(generation)) {
            bool valid = false;
            const auto value = request.toULongLong(&valid);
            status = valid && value && request == QString::number(value)
                ? library().jc_session_ack_dns_routes(handle, generation, value, applied ? 1 : 0) : JC_INVALID_ARGUMENT;
        }
        emit dnsRoutesResult(id, requestedGeneration, request, status);
    }
    void poll() {
        if (!active || QThread::currentThread()->isInterruptionRequested()) return;
        QByteArray buffer(JC_MAX_OUTPUT, Qt::Uninitialized);
        uint32_t length = 0;
        const int status = library().jc_session_read(handle, 100,
            reinterpret_cast<uint8_t *>(buffer.data()), uint32_t(buffer.size()), &length);
        if (status == JC_TIMEOUT || status == JC_CANCELLED) {
            QTimer::singleShot(status == JC_CANCELLED ? 10 : 0, this, &CoreEventPump::poll);
            return;
        }
        QJsonParseError error{};
        const auto doc = length <= uint32_t(buffer.size())
            ? QJsonDocument::fromJson(buffer.first(length), &error) : QJsonDocument();
        if (status != JC_OK || error.error != QJsonParseError::NoError || !doc.isObject()
            || doc.object()["schema_version"].toInt() != JC_ABI_VERSION
            || doc.object()["generation"].toString() != QString::number(generation)) {
            stop();
            while (library().jc_session_destroy(handle, JC_MAX_WAIT_MS) == JC_TIMEOUT) {}
            handle = 0; active = false;
            emit failed(serial, JC_INTERNAL); return;
        }
        const auto event = doc.object();
        if (event["type"] == "terminal") active = false;
        // The receiver acknowledges each event: at most one Qt event is in flight.
        const bool starting = event["type"] == "state" && event["state"] == "starting";
        const auto protection = starting ? initialPolicy : QJsonObject{};
        if (starting) initialPolicy = {};
        emit received(serial, event, protection);
    }
signals:
    void received(quint64 serial, const QJsonObject &event, const QJsonObject &initialPolicy);
    void failed(quint64 serial, int status);
    void accepted(quint64 serial);
    void rejected(quint64 serial);
    void policyResult(quint64 serial, const QString &generation, const QString &revision, int status);
    void dnsRoutesResult(quint64 serial, const QString &generation, const QString &request, int status);
    void tunResult(quint64 serial, const QString &generation, int status);
    void snapshotResult(quint64 serial, CoreEngine::Snapshot kind, const QString &generation, const QJsonObject &snapshot, int status);
};

EmbeddedCoreEngine::EmbeddedCoreEngine(QObject *parent) : CoreEngine(parent), pump(new CoreEventPump) {
    pump->moveToThread(&thread);
    connect(&thread, &QThread::finished, pump, &QObject::deleteLater);
    connect(pump, &CoreEventPump::received, this, &EmbeddedCoreEngine::deliver, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::failed, this, [this](quint64 id, int status) {
        if (!active || id != serial) return;
        active = false;
        emit finished(connectionError(status));
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::rejected, this, [this](quint64 id) {
        if (active && id == serial && !stopping) emit responseRejected();
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::accepted, this, [this](quint64 id) {
        if (active && id == serial && !stopping) emit responseAccepted();
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::policyResult, this, [this](quint64 id, const QString &generation, const QString &revision, int status) {
        if (id != serial) return;
        emit policyUpdated(generation, revision, !active || stopping ? RequestStatus::Stale : requestStatus(status));
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::snapshotResult, this, [this](quint64 id, Snapshot kind, const QString &generation, const QJsonObject &snapshot, int status) {
        if (id != serial) return;
        const bool stale = !active || stopping;
        emit snapshotReady(kind, generation, stale ? QJsonObject{} : snapshot, stale ? RequestStatus::Stale : requestStatus(status));
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::dnsRoutesResult, this, [this](quint64 id, const QString &generation, const QString &request, int status) {
        if (id == serial) emit dnsRoutesAcknowledged(generation, request, !active || stopping ? RequestStatus::Stale : requestStatus(status));
    }, Qt::QueuedConnection);
    connect(pump, &CoreEventPump::tunResult, this, [this](quint64 id, const QString &generation, int status) {
        if (id == serial) emit tunAttached(generation, !active || stopping ? RequestStatus::Stale : requestStatus(status));
    }, Qt::QueuedConnection);
    thread.start();
}
EmbeddedCoreEngine::~EmbeddedCoreEngine() {
    active = false;
    pump->cancelled.store(true);
    thread.requestInterruption();
    thread.quit();
    thread.wait();
}
bool EmbeddedCoreEngine::start(const ConnectionProfile &profile, Operation operation) {
    if (active) return false;
    active = true; stopping = false;
    pump->cancelled.store(false);
    const auto id = ++serial;
    auto config = configurationBytes(profile, operation);
    QMetaObject::invokeMethod(pump, [this, id, config] { pump->start(id, config); }, Qt::QueuedConnection);
    return true;
}
ConnectionError EmbeddedCoreEngine::validateConfiguration(const ConnectionProfile &profile) {
    auto &api = library();
    if (!api.available) return ConnectionError::CORE_UNAVAILABLE;
    auto bytes = configurationBytes(profile, Operation::Connect);
    const int status = api.jc_config_validate(JC_ABI_VERSION,
        reinterpret_cast<const uint8_t *>(bytes.constData()), uint32_t(bytes.size()));
    bytes.fill('\0');
    return connectionError(status);
}
void EmbeddedCoreEngine::stop() {
    if (!active || stopping) return;
    stopping = true;
    pump->cancelled.store(true);
    QMetaObject::invokeMethod(pump, &CoreEventPump::stop, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::respond(const QJsonObject &response) {
    if (!active || stopping) return;
    auto bytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
    if (bytes.size() > JC_MAX_INPUT) bytes.clear();
    QMetaObject::invokeMethod(pump, [this, bytes] { pump->respond(bytes); }, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::updatePolicy(const QJsonObject &policy) {
    const auto generation = policy["generation"].toString(), revision = policy["revision"].toString();
    if (!active || stopping) { emit policyUpdated(generation, revision, RequestStatus::Stale); return; }
    auto bytes = QJsonDocument(policy).toJson(QJsonDocument::Compact);
    if (bytes.size() > JC_MAX_INPUT) bytes.clear();
    const auto id = serial;
    QMetaObject::invokeMethod(pump, [this, id, bytes, generation, revision] { pump->updatePolicy(id, bytes, generation, revision); }, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::readSnapshot(Snapshot kind, const QString &generation) {
    if (!active || stopping) { emit snapshotReady(kind, generation, {}, RequestStatus::Stale); return; }
    const auto id = serial;
    QMetaObject::invokeMethod(pump, [this, id, kind, generation] { pump->readSnapshot(id, kind, generation); }, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::attachTUN(const QString &generation, qint32 descriptor, quint32 mtu, bool publishDNSRoutes) {
    if (!active || stopping) { emit tunAttached(generation, RequestStatus::Stale); return; }
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    if (!library().jc_session_attach_tun || !buildInfo()["capabilities"].toObject()["raw_ipv4_tun_fd"].toBool()
        || (publishDNSRoutes && (!library().jc_session_attach_tun_dns || !library().jc_session_ack_dns_routes
            || !buildInfo()["capabilities"].toObject()["tun_dns_routes"].toBool()))) {
        emit tunAttached(generation, RequestStatus::Unavailable); return;
    }
    const int copied = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
    if (copied < 0) { emit tunAttached(generation, RequestStatus::Invalid); return; }
    const auto held = std::shared_ptr<int>(new int(copied), [](int *value) { ::close(*value); delete value; });
    const auto id = serial;
    QMetaObject::invokeMethod(pump, [this, id, generation, held, mtu, publishDNSRoutes] { pump->attachTUN(id, generation, *held, mtu, publishDNSRoutes); }, Qt::QueuedConnection);
#else
    Q_UNUSED(descriptor); Q_UNUSED(mtu); Q_UNUSED(publishDNSRoutes);
    emit tunAttached(generation, RequestStatus::Unavailable);
#endif
}
void EmbeddedCoreEngine::attachWindowsPipe(const QString &generation, quint64 handle, quint32 helperPID, quint32 mtu,
    const QString &source, const QString &peer, bool publishDNSRoutes) {
    if (!active || stopping) { emit tunAttached(generation, RequestStatus::Stale); return; }
#ifdef Q_OS_WIN
    const auto capabilities = buildInfo()["capabilities"].toObject();
    if (!library().jc_session_attach_windows_pipe || !capabilities["windows_ipv4_packet_pipe"].toBool()
        || (publishDNSRoutes && (!library().jc_session_ack_dns_routes || !capabilities["tun_dns_routes"].toBool()))) {
        emit tunAttached(generation, RequestStatus::Unavailable); return;
    }
    bool sourceValid = false, peerValid = false;
    const QHostAddress sourceAddress(source), peerAddress(peer);
    const auto sourceValue = sourceAddress.toIPv4Address(&sourceValid), peerValue = peerAddress.toIPv4Address(&peerValid);
    HANDLE copied = nullptr;
    if (!sourceValid || !peerValid || sourceAddress.toString() != source || peerAddress.toString() != peer
        || !handle || quint64(quintptr(handle)) != handle || !helperPID
        || !::DuplicateHandle(::GetCurrentProcess(), reinterpret_cast<HANDLE>(quintptr(handle)),
            ::GetCurrentProcess(), &copied, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        emit tunAttached(generation, RequestStatus::Invalid); return;
    }
    const auto held = std::shared_ptr<void>(copied, [](void *value) { ::CloseHandle(value); });
    const auto id = serial;
    QMetaObject::invokeMethod(pump, [this, id, generation, held, helperPID, mtu, sourceValue, peerValue, publishDNSRoutes] {
        pump->attachWindowsPipe(id, generation, quint64(reinterpret_cast<quintptr>(held.get())), helperPID, mtu, sourceValue, peerValue, publishDNSRoutes);
    }, Qt::QueuedConnection);
#else
    Q_UNUSED(handle); Q_UNUSED(helperPID); Q_UNUSED(mtu); Q_UNUSED(source); Q_UNUSED(peer); Q_UNUSED(publishDNSRoutes);
    emit tunAttached(generation, RequestStatus::Unavailable);
#endif
}
void EmbeddedCoreEngine::acknowledgeDNSRoutes(const QString &generation, const QString &request, bool applied) {
    if (!active || stopping) { emit dnsRoutesAcknowledged(generation, request, RequestStatus::Stale); return; }
    if (!library().jc_session_ack_dns_routes) { emit dnsRoutesAcknowledged(generation, request, RequestStatus::Unavailable); return; }
    const auto id = serial;
    QMetaObject::invokeMethod(pump, [this, id, generation, request, applied] {
        pump->acknowledgeDNSRoutes(id, generation, request, applied);
    }, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::deliver(quint64 id, const QJsonObject &event, const QJsonObject &initialPolicy) {
    if (!active || id != serial) return;
    const auto type = event["type"].toString();
    if (type == "terminal") {
        active = false;
        const auto status = event["status"].toInt(JC_INTERNAL);
        emit finished(connectionError(status));
        return;
    }
    QMetaObject::invokeMethod(pump, &CoreEventPump::poll, Qt::QueuedConnection);
    if (stopping) return;
    if (type == "dns_routes") emit dnsRoutesRequired(event);
    else if (type == "authentication") emit authenticationRequired(event);
    else if (type=="authentication_cache") {
        if (event["action"]=="invalidate" && !event.contains("cache")) {
            emit authenticationCacheInvalidated();return;
        }
        const auto cache=event["cache"].toObject();
        const auto account=cache["account"].toString();
        const auto encoded=cache["data"].toString().toLatin1();
        if (event["action"]!="save" || cache.size()!=2 || !cache["account"].isString() || !cache["data"].isString()
            || account.isEmpty() || account.toUtf8().size()>JC_MAX_USERNAME || account.contains(QChar(0)) || account.contains(QChar(0xfffd))
            || encoded.size()>4*((JC_MAX_AUTH_CACHE+2)/3)) {emit diagnostic("persistence_failed");return;}
        const auto decoded=QByteArray::fromBase64Encoding(encoded,QByteArray::AbortOnBase64DecodingErrors);
        if (!decoded || decoded.decoded.isEmpty() || decoded.decoded.size()>JC_MAX_AUTH_CACHE || decoded.decoded.toBase64()!=encoded) {
            emit diagnostic("persistence_failed");return;
        }
        emit authenticationCacheUpdated({account,decoded.decoded});
    }
    else if (type == "observation") {
        const auto stage=event["stage"].toString(), result=event["result"].toString();
        const auto observed=QDateTime::fromString(event["observed_at"].toString(),Qt::ISODateWithMs);
        if (QStringList{"authentication","restore","renewal","traffic","nodes","tunnel"}.contains(stage)
            && QStringList{"running","succeeded","failed","required","disabled","unavailable","unknown"}.contains(result) && observed.isValid())
            emit observation(stage,result,observed);
    }
    else if (type == "auth_methods") emit authMethodsReady(event["methods"].toArray());
    else if (type == "diagnostic") emit diagnostic(event["code"].toString());
    else if (type == "state" && event["state"] == "starting") {
        emit observation("library","succeeded",QDateTime::currentDateTimeUtc());
        emit sessionStarted(event["generation"].toString());
        if (!initialPolicy.isEmpty()) emit initialProtectionApplied(initialPolicy);
    }
    else if (type == "state" && event["state"] == "ready") { emit connectionEstablished(); }
}
QJsonObject EmbeddedCoreEngine::buildInfo() {
    auto &api = library();
    if (!api.available) return {};
    QByteArray buffer(JC_MAX_OUTPUT, Qt::Uninitialized);
    uint32_t length = 0;
    if (api.jc_build_info(JC_ABI_VERSION, reinterpret_cast<uint8_t *>(buffer.data()),
            uint32_t(buffer.size()), &length) != JC_OK || length > uint32_t(buffer.size())) return {};
    return QJsonDocument::fromJson(buffer.first(length)).object();
}

QJsonObject EmbeddedCoreEngine::selfTest() {
    auto info = buildInfo();
    auto &api = library();
    const auto capabilities = info["capabilities"].toObject();
    bool ok = api.available && info["abi_version"].toInt() == JC_ABI_VERSION
        && info["test_driver"].isBool() && !info["test_driver"].toBool()
        && capabilities["embedded_vpn"].toBool() && api.jc_network_snapshot
        && capabilities["network_snapshot"].toBool() && capabilities["initial_protection"].toBool() && capabilities["name_protection"].toBool();
    uint64_t handle = 0;
    if (ok) {
        ok = api.jc_session_create(JC_ABI_VERSION, &handle) == JC_OK && handle != 0;
        if (handle) {
            // Invalid input exercises the ABI without starting networking or changing host settings.
            const uint8_t invalid[] = {'{', '}'};
            ok = api.jc_config_validate(JC_ABI_VERSION, invalid, sizeof invalid) == JC_INVALID_ARGUMENT && ok;
            uint64_t generation = 0;
            ok = api.jc_session_start(handle, invalid, sizeof invalid, &generation) == JC_INVALID_ARGUMENT && ok;
            ok = api.jc_session_stop(handle, JC_MAX_WAIT_MS) == JC_OK && ok;
            ok = api.jc_session_destroy(handle, JC_MAX_WAIT_MS) == JC_OK && ok;
            ok = api.jc_session_destroy(handle, 0) == JC_OK && ok;
        }
    }
    return {{"ok", ok}, {"core", info},
#ifdef JC_SHARED_LIBRARY
        {"runtime", QStringLiteral(JC_SHARED_LIBRARY)}
#else
        {"runtime", "static"}
#endif
    };
}

#include "embeddedcoreengine.moc"
