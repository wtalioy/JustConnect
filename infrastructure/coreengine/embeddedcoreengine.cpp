#include "embeddedcoreengine.h"
#include "justconnect.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QLibrary>
#include <QTimer>

namespace {
#define CORE_FUNCTIONS(X) X(jc_abi_version) X(jc_build_info) X(jc_config_validate) X(jc_session_create) X(jc_session_start) \
    X(jc_session_read) X(jc_session_respond) X(jc_session_stop) X(jc_session_destroy)
struct Library {
#define MEMBER(name) decltype(&::name) name = nullptr;
    CORE_FUNCTIONS(MEMBER)
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
    if (status == JC_CREDENTIALS_REQUIRED) return ConnectionError::CREDENTIALS_REQUIRED;
    if (status == JC_AUTH_METHOD_CHANGED) return ConnectionError::AUTHENTICATION_CHANGED;
    if (status == JC_INVALID_ARGUMENT) return ConnectionError::INVALID_CONFIGURATION;
    if (status == JC_UNSUPPORTED || status == JC_ABI_MISMATCH) return ConnectionError::CORE_UNAVAILABLE;
    return ConnectionError::CLIENT_FAILED;
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
    ~CoreEventPump() override {
        if (!handle) return;
        // No ABI call or borrowed buffer may outlive this worker.
        while (library().jc_session_destroy(handle, JC_MAX_WAIT_MS) == JC_TIMEOUT) {}
    }
    void start(quint64 nextSerial, QByteArray config) {
        serial = nextSerial;
        auto &api = library();
        int status = JC_UNSUPPORTED;
        if (api.available) {
            status = handle ? JC_OK : api.jc_session_create(JC_ABI_VERSION, &handle);
            if (status == JC_OK)
                status = api.jc_session_start(handle, reinterpret_cast<const uint8_t *>(config.constData()),
                    uint32_t(config.size()), &generation);
        }
        config.fill('\0');
        if (status != JC_OK) { emit failed(serial, status); return; }
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
        QJsonParseError error;
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
        emit received(serial, event);
    }
signals:
    void received(quint64 serial, const QJsonObject &event);
    void failed(quint64 serial, int status);
    void accepted(quint64 serial);
    void rejected(quint64 serial);
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
    thread.start();
}
EmbeddedCoreEngine::~EmbeddedCoreEngine() {
    active = false;
    thread.requestInterruption();
    thread.quit();
    thread.wait();
}
bool EmbeddedCoreEngine::start(const ConnectionProfile &profile, Operation operation) {
    if (active) return false;
    active = true; stopping = false; established = false;
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
    QMetaObject::invokeMethod(pump, &CoreEventPump::stop, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::respond(const QJsonObject &response) {
    if (!active || stopping) return;
    auto bytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
    if (bytes.size() > JC_MAX_INPUT) bytes.clear();
    QMetaObject::invokeMethod(pump, [this, bytes] { pump->respond(bytes); }, Qt::QueuedConnection);
}
void EmbeddedCoreEngine::deliver(quint64 id, const QJsonObject &event) {
    if (!active || id != serial) return;
    const auto type = event["type"].toString();
    if (type == "terminal") {
        active = false;
        const auto status = event["status"].toInt(JC_INTERNAL);
        emit finished(established && status != JC_OK && status != JC_CANCELLED
            ? ConnectionError::OTHER : connectionError(status));
        return;
    }
    QMetaObject::invokeMethod(pump, &CoreEventPump::poll, Qt::QueuedConnection);
    if (stopping) return;
    if (type == "authentication") emit authenticationRequired(event);
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
    else if (type == "auth_methods") emit authMethodsReady(event["methods"].toArray());
    else if (type == "diagnostic") emit diagnostic(event["code"].toString());
    else if (type == "state" && event["state"] == "ready") { established = true; emit connectionEstablished(); }
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
    bool ok = api.available && info["abi_version"].toInt() == JC_ABI_VERSION
        && info["test_driver"].isBool() && !info["test_driver"].toBool()
        && info["capabilities"].toObject()["embedded_vpn"].toBool();
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
