#include "infrastructure/systemproxy/platformsystemproxybackend.h"
#include "infrastructure/systemproxy/proxyvalidation.h"
#include "application/credentialstore.h"
#include <QJsonDocument>
#include <QSysInfo>
#include <QUuid>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;

struct Key { const char *schema; const char *key; };
constexpr Key ModeKey{"org.gnome.system.proxy", "mode"};
constexpr Key AutoconfigKey{"org.gnome.system.proxy", "autoconfig-url"};
constexpr Key IgnoreHostsKey{"org.gnome.system.proxy", "ignore-hosts"};
constexpr Key HttpHostKey{"org.gnome.system.proxy.http", "host"};
constexpr Key HttpPortKey{"org.gnome.system.proxy.http", "port"};
constexpr Key HttpAuthKey{"org.gnome.system.proxy.http", "use-authentication"};
constexpr Key HttpsHostKey{"org.gnome.system.proxy.https", "host"};
constexpr Key HttpsPortKey{"org.gnome.system.proxy.https", "port"};
constexpr Key FtpHostKey{"org.gnome.system.proxy.ftp", "host"};
constexpr Key FtpPortKey{"org.gnome.system.proxy.ftp", "port"};
constexpr Key SocksHostKey{"org.gnome.system.proxy.socks", "host"};
constexpr Key SocksPortKey{"org.gnome.system.proxy.socks", "port"};

// Ownership groups mirror the macOS endpoint groups; HTTP authentication rides the HTTP group.
constexpr unsigned ModeFields = 1, AutoconfigFields = 2, IgnoreFields = 4;
constexpr unsigned HttpFields = 8, HttpsFields = 16, FtpFields = 32, SocksFields = 64;
constexpr unsigned ProtocolFields = HttpFields | HttpsFields | FtpFields | SocksFields;
constexpr unsigned AllFields = 127;

struct Group { unsigned bit; std::vector<Key> keys; };
const std::vector<Group> groups = {
    {ModeFields, {ModeKey}},
    {AutoconfigFields, {AutoconfigKey}},
    {IgnoreFields, {IgnoreHostsKey}},
    {HttpFields, {HttpHostKey, HttpPortKey, HttpAuthKey}},
    {HttpsFields, {HttpsHostKey, HttpsPortKey}},
    {FtpFields, {FtpHostKey, FtpPortKey}},
    {SocksFields, {SocksHostKey, SocksPortKey}},
};

QString keyName(const Key &key) { return QString::fromLatin1(key.schema) + '/' + QString::fromLatin1(key.key); }

// GVariant textual strings accept single quotes; backslashes and the quote itself are escaped.
QString variantString(QString value) {
    value.replace('\\', "\\\\"); value.replace('\'', "\\'");
    return '\'' + value + '\'';
}
QString variantArray(const QStringList &items) {
    QStringList encoded;
    for (const auto &item : items) encoded.append(variantString(item));
    return '[' + encoded.join(QStringLiteral(", ")) + ']';
}
QString unquote(const QJsonValue &value) {
    auto text = value.toString();
    if (text.size() >= 2 && (text.front() == '\'' || text.front() == '"') && text.back() == text.front()) {
        text = text.mid(1, text.size() - 2);
        text.replace("\\'", "'"); text.replace("\\\"", "\""); text.replace("\\\\", "\\");
    }
    return text;
}

Result readState(const LinuxProxyApi &api, QJsonObject &state) {
    for (const auto &group : groups)
        for (const auto &key : group.keys) {
            const auto value = api.read(QString::fromLatin1(key.schema), QString::fromLatin1(key.key));
            if (!value) return {Status::Unsupported, "System proxy settings are unavailable through gsettings"};
            state[keyName(key)] = *value;
        }
    return {};
}

bool groupEquals(const QJsonObject &a, const QJsonObject &b, unsigned bit) {
    for (const auto &group : groups) if (group.bit == bit) {
        for (const auto &key : group.keys) if (a[keyName(key)] != b[keyName(key)]) return false;
        return true;
    }
    return false;
}

QJsonObject requested(const QJsonObject &before, const SystemProxyConfig &config, unsigned bits) {
    QJsonObject installed = before;
    if (bits & ModeFields) installed[keyName(ModeKey)] = variantString(QStringLiteral("manual"));
    if (bits & IgnoreFields) installed[keyName(IgnoreHostsKey)] = variantArray(ProxyValidation::bypass(config.bypass));
    if (bits & HttpFields) {
        installed[keyName(HttpHostKey)] = variantString(QStringLiteral("127.0.0.1"));
        installed[keyName(HttpPortKey)] = QString::number(config.httpPort);
        // Leave the saved credentials untouched and disable authentication on the local endpoint.
        installed[keyName(HttpAuthKey)] = QStringLiteral("false");
    }
    if (bits & HttpsFields) {
        installed[keyName(HttpsHostKey)] = variantString(QStringLiteral("127.0.0.1"));
        installed[keyName(HttpsPortKey)] = QString::number(config.httpPort);
    }
    if (bits & FtpFields) {
        installed[keyName(FtpHostKey)] = variantString(QStringLiteral("127.0.0.1"));
        installed[keyName(FtpPortKey)] = QString::number(config.httpPort);
    }
    if (bits & SocksFields) {
        installed[keyName(SocksHostKey)] = variantString(QStringLiteral("127.0.0.1"));
        installed[keyName(SocksPortKey)] = QString::number(config.socksPort);
    }
    return installed;
}

bool enabled(const QJsonObject &state, const Key &host) { return !unquote(state[keyName(host)]).isEmpty(); }

int endpointPort(const QJsonObject &state, const Key &port) {
    bool valid = false;
    const int value = unquote(state[keyName(port)]).toInt(&valid);
    return valid ? value : -1;
}

QStringList protocolEndpoints(const QJsonObject &state, unsigned bit) {
    const Key *host = nullptr, *port = nullptr;
    for (const auto &group : groups) if (group.bit == bit && group.keys.size() >= 2) { host = &group.keys[0]; port = &group.keys[1]; }
    if (!host || !enabled(state, *host)) return {};
    const auto endpoint = ProxyValidation::localEndpoint(unquote(state[keyName(*host)]), endpointPort(state, *port));
    return endpoint.isEmpty() ? QStringList{} : QStringList{endpoint};
}

QStringList proxyEndpoints(const QJsonObject &state) {
    if (unquote(state[keyName(ModeKey)]) != QStringLiteral("manual")) return {};
    QStringList result;
    for (const auto &group : groups) {
        if (group.bit < HttpFields || group.keys.size() < 2) continue;
        if (!enabled(state, group.keys[0])) continue;
        // Any manual endpoint that cannot be classified blocks the loopback handoff list entirely.
        const auto endpoint = ProxyValidation::localEndpoint(unquote(state[keyName(group.keys[0])]), endpointPort(state, group.keys[1]));
        if (endpoint.isEmpty()) return {};
        if (!result.contains(endpoint)) result.append(endpoint);
    }
    return result;
}

Result writeGroups(const LinuxProxyApi &api, const QJsonObject &values, unsigned bits) {
    for (const auto &group : groups) if (bits & group.bit)
        for (const auto &key : group.keys)
            if (auto write = api.write(QString::fromLatin1(key.schema), QString::fromLatin1(key.key),
                                       values[keyName(key)].toString());
                !write.succeeded()) return write;
    return {Status::Success, {}, true};
}
}

struct PlatformSystemProxyBackend::Snapshot {
    unsigned released = 0, intent = 0, written = 0, uncertain = 0, pendingRestore = 0;
    QJsonObject before, installed;
    SystemProxyConfig config;
    QUuid owner = QUuid::createUuid();
    bool dirty = false, resumed = false;
};

QJsonObject PlatformSystemProxyBackend::recoverySnapshot() const {
    if (!snapshot) return {};
    return {{"schema_version", 1}, {"platform", "linux"},
        {"machine", QString::fromLatin1(QSysInfo::machineUniqueId().toHex())},
        {"uid", qint64(geteuid())},
        {"owner", snapshot->owner.toString(QUuid::WithoutBraces)},
        {"config", ProxyValidation::json(snapshot->config)},
        {"before", snapshot->before},
        {"released", qint64(snapshot->released)}, {"intent", qint64(snapshot->intent)},
        {"written", qint64(snapshot->written)}, {"uncertain", qint64(snapshot->uncertain)},
        {"pending_restore", qint64(snapshot->pendingRestore)}};
}

PlatformOperationResult PlatformSystemProxyBackend::checkpoint(bool remove) {
    auto result = checkpointWriter ? checkpointWriter(remove ? QJsonObject{} : recoverySnapshot()) : Result{};
    if (!result.succeeded() && snapshot && snapshot->dirty) result.mayHaveChanged = true;
    return result;
}

PlatformOperationResult PlatformSystemProxyBackend::recover(const QJsonObject &record) {
    if (snapshot) return {Status::Failed, "Existing system proxy ownership must be restored first", true};
    const auto invalid = [] { return Result{Status::Failed, "Invalid or foreign Linux proxy recovery record"}; };
    const auto bytes = QJsonDocument(record).toJson(QJsonDocument::Compact);
    const auto machine = QString::fromLatin1(QSysInfo::machineUniqueId().toHex());
    const auto ownerText = record["owner"].toString();
    const QUuid owner(ownerText);
    if (bytes.size() > CredentialStore::MaxBytes || QJsonDocument::fromJson(bytes).object() != record || record.size() != 12
        || record["schema_version"] != 1 || record["platform"] != "linux" || machine.isEmpty()
        || record["machine"] != machine || record["uid"].toInteger(-1) != qint64(geteuid())
        || owner.isNull() || owner.toString(QUuid::WithoutBraces) != ownerText
        || !record["config"].isObject() || !record["before"].isObject()) return invalid();
    const auto config = ProxyValidation::parse(record["config"].toObject());
    if (!config) return invalid();
    auto pending = std::make_shared<Snapshot>();
    pending->owner = owner;
    pending->config = *config;
    if (!ProxyValidation::config(pending->config).succeeded()) return invalid();
    const auto before = record["before"].toObject();
    for (auto it = before.begin(); it != before.end(); ++it)
        if (!it.value().isString() || it.value().toString().contains(QChar(0))) return invalid();
    for (const auto &group : groups)
        for (const auto &key : group.keys)
            if (!before.contains(keyName(key))) return invalid();
    for (const auto &field : std::initializer_list<std::pair<const char *, unsigned *>>{
             {"released", &pending->released}, {"intent", &pending->intent}, {"written", &pending->written},
             {"uncertain", &pending->uncertain}, {"pending_restore", &pending->pendingRestore}}) {
        const auto value = record[field.first].toInteger(-1);
        if (value < 0 || value > AllFields) return invalid();
        *field.second = unsigned(value);
    }
    if ((pending->written & ~pending->intent) || (pending->uncertain & ~pending->intent)
        || (pending->released & pending->uncertain)
        || (pending->pendingRestore & (~pending->intent | pending->released | pending->uncertain))) return invalid();
    // The recorded intent exactly reproduces which groups the crashed owner had installed.
    pending->before = before;
    pending->installed = requested(before, pending->config, pending->intent);
    pending->dirty = pending->intent != 0;
    pending->resumed = true;
    snapshot = pending;
    return clear();
}

SystemProxyCheck PlatformSystemProxyBackend::check(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return {valid};
    return observe(&config);
}

SystemProxyCheck PlatformSystemProxyBackend::inspect() { return observe(nullptr); }

SystemProxyCheck PlatformSystemProxyBackend::observe(const SystemProxyConfig *config) {
    QJsonObject current;
    if (auto result = readState(api, current); !result.succeeded()) return {result};
    const auto mode = unquote(current[keyName(ModeKey)]);
    bool active = false, conflict = false, managed = false, own = false;
    QStringList observed;
    const QJsonObject *upstream = &current;
    if (snapshot) {
        own = true;
        for (const auto &group : groups) if (snapshot->intent & group.bit) own &= groupEquals(current, snapshot->installed, group.bit);
        if (own) upstream = &snapshot->before;
    }
    if (mode == QStringLiteral("auto")) {
        conflict = true; // An active PAC configuration cannot host the manual local handoff.
    } else if (mode == QStringLiteral("manual")) {
        bool anyEndpoint = false;
        for (const auto &group : groups) {
            if (group.bit < HttpFields || group.keys.size() < 2) continue;
            if (!enabled(current, group.keys[0])) continue;
            anyEndpoint = true;
            if (config) {
                conflict |= unquote(current[keyName(group.keys[0])]) != QStringLiteral("127.0.0.1")
                    || endpointPort(current, group.keys[1]) != (group.bit == SocksFields ? config->socksPort : config->httpPort)
                    || (group.bit == HttpFields && unquote(current[keyName(HttpAuthKey)]) == QStringLiteral("true"));
            }
        }
        active = anyEndpoint;
        managed = own && !proxyEndpoints(current).isEmpty();
        for (const auto &endpoint : proxyEndpoints(*upstream))
            if (!observed.contains(endpoint)) observed.append(endpoint);
    }
    return {{}, conflict, active, managed && active, observed};
}

PlatformOperationResult PlatformSystemProxyBackend::apply(const SystemProxyConfig &config) {
    if (auto valid = ProxyValidation::config(config); !valid.succeeded()) return valid;
    if (snapshot) return {Status::Failed, "Restore the current proxy settings before applying another configuration", true};
    QJsonObject before;
    if (auto result = readState(api, before); !result.succeeded()) return result;
    const bool handoff = !config.upstream.isEmpty();
    unsigned intent = 0;
    for (const auto bit : {HttpFields, HttpsFields, FtpFields, SocksFields}) {
        if (handoff && !ProxyValidation::matches(config.upstream, protocolEndpoints(before, bit))) continue;
        if (groupEquals(before, requested(before, config, bit), bit)) continue;
        intent |= bit;
    }
    if (!handoff) {
        if (unquote(before[keyName(ModeKey)]) != QStringLiteral("manual")) intent |= ModeFields;
        if (before[keyName(IgnoreHostsKey)] != variantArray(ProxyValidation::bypass(config.bypass))) intent |= IgnoreFields;
    }
    if (handoff && !(intent & ProtocolFields)) return {Status::Failed, "System proxy changed before automatic handoff"};
    auto pending = std::make_shared<Snapshot>();
    pending->config = config;
    pending->before = before;
    pending->installed = requested(before, config, intent);
    pending->intent = intent;
    snapshot = pending;
    if (auto result = checkpoint(); !result.succeeded()) {
        if (!result.mayHaveChanged) snapshot.reset();
        return result;
    }
    pending->dirty = pending->intent != 0;
    if (auto result = checkpoint(); !result.succeeded()) return result;
    QJsonObject current;
    if (auto result = readState(api, current); !result.succeeded()) return result;
    if (current != before) return {Status::Failed, "Proxy settings changed while recording application intent", true};
    const auto fail = [this](Result result) { const auto restored = clear(); result.mayHaveChanged = !restored.succeeded(); return result; };
    const auto abandon = [&](Result result) {
        pending->intent = 0;
        pending->released = AllFields;
        return fail(result);
    };
    const auto written = writeGroups(api, pending->installed, pending->intent);
    if (!written.succeeded()) return fail(written);
    if (auto result = readState(api, current); !result.succeeded()) return fail(result);
    for (const auto &group : groups) if (pending->intent & group.bit)
        for (const auto &key : group.keys)
            if (current[keyName(key)] != pending->installed[keyName(key)])
                return fail({Status::Failed, "GNOME proxy readback mismatch", true});
    pending->written = pending->intent;
    if (auto result = checkpoint(); !result.succeeded()) return fail(result);
    return {Status::Success, {}, true};
}

PlatformOperationResult PlatformSystemProxyBackend::clear() {
    if (!snapshot) return {};
    auto &saved = *snapshot;
    const auto failed = [](Result result) { result.mayHaveChanged = true; return result; };
    const auto releaseObserved = [&](const QJsonObject &value) {
        saved.released |= AllFields & ~saved.intent;
        for (const auto &group : groups) {
            const auto bit = group.bit;
            if (!(saved.intent & bit) || (saved.released & bit)) continue;
            // An original value already back in place, or any foreign value, ends our ownership.
            if (groupEquals(value, saved.before, bit) || !groupEquals(value, saved.installed, bit)) {
                saved.released |= bit;
                saved.uncertain &= ~bit;
            }
        }
        saved.pendingRestore &= ~saved.released;
    };
    if (!saved.dirty) {
        if (auto result = checkpoint(true); !result.succeeded()) return failed(result);
        snapshot.reset();
        return {};
    }
    if (saved.resumed) {
        const auto pendingRestore = saved.pendingRestore;
        // Save before observing originals: a crash may otherwise lose a released field's ownership.
        const auto unconfirmed = ((saved.intent & ~saved.written) | pendingRestore) & ~saved.released;
        saved.pendingRestore = saved.intent & ~(saved.released | saved.uncertain);
        if (auto result = checkpoint(); !result.succeeded()) { saved.pendingRestore = pendingRestore; return failed(result); }
        QJsonObject current;
        if (auto result = readState(api, current); !result.succeeded()) { saved.pendingRestore = pendingRestore; return failed(result); }
        releaseObserved(current);
        // A lost acknowledgement cannot distinguish our setting from an external same-value recreation.
        saved.uncertain |= unconfirmed & ~saved.released;
        saved.pendingRestore = 0;
        if (auto result = checkpoint(); !result.succeeded()) return failed(result);
        saved.resumed = false;
    }
    QJsonObject current;
    if (auto result = readState(api, current); !result.succeeded()) return failed(result);
    saved.pendingRestore = saved.intent & ~(saved.released | saved.uncertain);
    if (auto result = checkpoint(); !result.succeeded()) return failed(result);
    releaseObserved(current);
    for (;;) {
        const auto fields = saved.intent & ~(saved.released | saved.uncertain);
        saved.pendingRestore = fields;
        if (auto result = checkpoint(); !result.succeeded()) return failed(result);
        if (!fields) break;
        const auto released = saved.released;
        if (auto result = readState(api, current); !result.succeeded()) return failed(result);
        releaseObserved(current);
        if (released != saved.released) continue;
        if (auto result = writeGroups(api, saved.before, fields); !result.succeeded()) return failed(result);
        if (auto result = readState(api, current); !result.succeeded()) return failed(result);
        releaseObserved(current);
        if (auto result = checkpoint(); !result.succeeded()) return failed(result);
        for (const auto &group : groups) if (fields & group.bit)
            for (const auto &key : group.keys)
                if (current[keyName(key)] != saved.before[keyName(key)])
                    return {Status::Failed, "GNOME restoration readback mismatch", true};
        break;
    }
    if (saved.released != AllFields) return {Status::Failed, "Unconfirmed proxy settings retained; external ownership cannot be determined", true};
    if (auto result = checkpoint(true); !result.succeeded()) return failed(result);
    snapshot.reset();
    return {};
}
