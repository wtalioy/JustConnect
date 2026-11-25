#include "infrastructure/systemproxy/proxychanges.h"
#include <QLibrary>
#include <QStringList>
#include <algorithm>
#include <chrono>
#include <functional>
#include <vector>

// GLib/GIO are always present on a Linux desktop, so bind to libgio/libgobject/libglib
// directly and subscribe to the org.gnome.system.proxy "changed" signals instead of
// polling `gsettings` from a subprocess every two seconds. GSettings only fires on
// real writes, and each notification re-reads the full snapshot so a burst of key
// writes coalesces into a single emission on actual value movement.
namespace {

using GCallbackFn = void (*)();

const char *const GioLibrary = "libgio-2.0.so.0";
const char *const GObjectLibrary = "libgobject-2.0.so.0";
const char *const GlibLibrary = "libglib-2.0.so.0";
const char *const ProxySchemas[] = {
    "org.gnome.system.proxy",
    "org.gnome.system.proxy.http", "org.gnome.system.proxy.https",
    "org.gnome.system.proxy.ftp", "org.gnome.system.proxy.socks"
};

struct GioApi {
    void *(*schemaSourceGetDefault)() = nullptr;
    void *(*schemaSourceLookup)(void *, const char *, int) = nullptr;
    void (*schemaUnref)(void *) = nullptr;
    char **(*schemaListKeys)(void *) = nullptr;
    void *(*settingsNew)(const char *) = nullptr;
    void *(*settingsGetValue)(void *, const char *) = nullptr;
    unsigned long (*signalConnectData)(void *, const char *, GCallbackFn, void *, void (*)(void *, void *), int) = nullptr;
    void (*signalHandlerDisconnect)(void *, unsigned long) = nullptr;
    void (*objectUnref)(void *) = nullptr;
    const char *(*variantGetTypeString)(void *) = nullptr;
    // g_variant_get_string / g_variant_dup_strv both take a gsize* length out-param.
    const char *(*variantGetString)(void *, unsigned long *) = nullptr;
    int (*variantGetInt32)(void *) = nullptr;
    unsigned (*variantGetUint32)(void *) = nullptr;
    char **(*variantGetStrv)(void *, unsigned long *) = nullptr;
    int (*variantGetBoolean)(void *) = nullptr;
    void (*variantUnref)(void *) = nullptr;
    void (*free)(void *) = nullptr;
    void (*strfreev)(char **) = nullptr;

    bool complete() const {
        return schemaSourceGetDefault && schemaSourceLookup && schemaUnref && schemaListKeys && settingsNew
            && settingsGetValue && signalConnectData && signalHandlerDisconnect && objectUnref
            && variantGetTypeString && variantGetString && variantGetInt32 && variantGetUint32
            && variantGetStrv && variantGetBoolean && variantUnref && free && strfreev;
    }
};

QString schemaValue(const GioApi &api, void *variant)
{
    const auto type = QByteArray(api.variantGetTypeString(variant));
    if (type == "s") {
        const auto text = api.variantGetString(variant, nullptr);
        return text ? QString::fromUtf8(text) : QString();
    }
    if (type == "i") return QString::number(api.variantGetInt32(variant));
    if (type == "u") return QString::number(api.variantGetUint32(variant));
    if (type == "b") return api.variantGetBoolean(variant) ? "true" : "false";
    if (type == "as") {
        const auto items = api.variantGetStrv(variant, nullptr);
        if (!items) return QString();
        QStringList entries;
        for (auto entry = items; *entry; ++entry) entries << QString::fromUtf8(*entry);
        api.strfreev(items);
        return entries.join(u'\x1F'); // A separator that never appears in a proxy value.
    }
    return QString(); // Unsupported value type: the key is ignored, not a failure.
}

// Deliver GSettings notifications on the Qt event loop instead of the glib dispatch.
void changedTrampoline(void *, const char *, void *data)
{
    QMetaObject::invokeMethod(static_cast<ProxyChanges *>(data), &ProxyChanges::noteSignal,
        Qt::QueuedConnection);
}
}

struct ProxyChanges::Watch {
    struct Observed { void *settings = nullptr; void *schema = nullptr; const char *schemaId = nullptr; unsigned long handler = 0; };

    GioApi api;
    std::function<QByteArray()> reader;
    QByteArray previous;
    ProxyChanges *observer = nullptr;
    std::vector<Observed> observed;

    ~Watch() {
        for (const auto &entry : observed) {
            api.signalHandlerDisconnect(entry.settings, entry.handler);
            api.objectUnref(entry.settings);
            api.schemaUnref(entry.schema);
        }
    }

    // Subscribe once: each managed schema that this desktop actually ships.
    void subscribe() {
        void *source = api.schemaSourceGetDefault();
        if (!source) return;
        for (const auto *schemaId : ProxySchemas) {
            void *schema = api.schemaSourceLookup(source, schemaId, 1);
            if (!schema) continue; // An absent optional child schema is not an error.
            void *settings = api.settingsNew(schemaId);
            if (!settings) { api.schemaUnref(schema); continue; }
            observed.push_back({settings, schema, schemaId,
                api.signalConnectData(settings, "changed", reinterpret_cast<GCallbackFn>(&changedTrampoline),
                    observer, nullptr, 0)});
        }
    }

    QByteArray readSnapshot() const {
        if (observed.empty()) return {};
        QByteArray joined;
        for (const auto &entry : observed) {
            const auto keys = api.schemaListKeys(entry.schema);
            if (!keys) continue;
            QStringList lines;
            for (auto key = keys; *key; ++key) {
                void *variant = api.settingsGetValue(entry.settings, *key);
                if (!variant) continue;
                const auto value = schemaValue(api, variant);
                api.variantUnref(variant);
                lines << QString("%1/%2=%3").arg(QString::fromUtf8(entry.schemaId), QString::fromUtf8(*key), value);
            }
            api.strfreev(keys);
            std::sort(lines.begin(), lines.end());
            for (const auto &line : lines) joined += line.toUtf8() + '\n';
        }
        return joined;
    }
};

ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>())
{
    watch->observer = this;
    // A settings write burst (mode plus per-protocol keys) fires one GSettings
    // signal per key; the snapshot read waits for the burst to settle so one
    // movement check and one emission serve the whole batch.
    batch.setSingleShot(true);
    batch.setInterval(std::chrono::milliseconds(150));
    connect(&batch, &QTimer::timeout, this, &ProxyChanges::handleSignal);
    QLibrary gio, gobject, glib;
    gio.setFileName(GioLibrary);
    gobject.setFileName(GObjectLibrary);
    glib.setFileName(GlibLibrary);
    if (!gio.load() || !gobject.load() || !glib.load()) return;
    auto &api = watch->api;
    api.schemaSourceGetDefault = reinterpret_cast<void *(*)()>(gio.resolve("g_settings_schema_source_get_default"));
    api.schemaSourceLookup = reinterpret_cast<void *(*)(void *, const char *, int)>(gio.resolve("g_settings_schema_source_lookup"));
    api.schemaUnref = reinterpret_cast<void (*)(void *)>(gio.resolve("g_settings_schema_unref"));
    api.schemaListKeys = reinterpret_cast<char **(*)(void *)>(gio.resolve("g_settings_schema_list_keys"));
    api.settingsNew = reinterpret_cast<void *(*)(const char *)>(gio.resolve("g_settings_new"));
    api.settingsGetValue = reinterpret_cast<void *(*)(void *, const char *)>(gio.resolve("g_settings_get_value"));
    api.signalConnectData = reinterpret_cast<unsigned long (*)(void *, const char *, GCallbackFn, void *, void (*)(void *, void *), int)>(gobject.resolve("g_signal_connect_data"));
    api.signalHandlerDisconnect = reinterpret_cast<void (*)(void *, unsigned long)>(gobject.resolve("g_signal_handler_disconnect"));
    api.objectUnref = reinterpret_cast<void (*)(void *)>(gobject.resolve("g_object_unref"));
    api.variantGetTypeString = reinterpret_cast<const char *(*)(void *)>(glib.resolve("g_variant_get_type_string"));
    api.variantGetString = reinterpret_cast<const char *(*)(void *, unsigned long *)>(glib.resolve("g_variant_get_string"));
    api.variantGetInt32 = reinterpret_cast<int (*)(void *)>(glib.resolve("g_variant_get_int32"));
    api.variantGetUint32 = reinterpret_cast<unsigned (*)(void *)>(glib.resolve("g_variant_get_uint32"));
    api.variantGetStrv = reinterpret_cast<char **(*)(void *, unsigned long *)>(glib.resolve("g_variant_dup_strv"));
    api.variantGetBoolean = reinterpret_cast<int (*)(void *)>(glib.resolve("g_variant_get_boolean"));
    api.variantUnref = reinterpret_cast<void (*)(void *)>(glib.resolve("g_variant_unref"));
    api.free = reinterpret_cast<void (*)(void *)>(glib.resolve("g_free"));
    api.strfreev = reinterpret_cast<void (*)(char **)>(glib.resolve("g_strfreev"));
    if (!api.complete()) return;

    watch->subscribe();
    // An empty snapshot means no usable dconf session: stay silent instead of
    // watching nothing, mirroring the old poller's guard.
    const auto initial = watch->readSnapshot();
    if (initial.isEmpty()) return;
    watch->previous = initial;
    watch->reader = [this] { return watch->readSnapshot(); };
}

void ProxyChanges::setSnapshotReader(std::function<QByteArray()> reader)
{
    watch->reader = std::move(reader);
}

void ProxyChanges::noteSignal()
{
    // The first notification of a burst opens the batch window; the rest of
    // the burst is absorbed while it runs and one read follows its expiry.
    if (!batch.isActive()) batch.start();
}

void ProxyChanges::handleSignal()
{
    if (!watch->reader) return;
    const auto current = watch->reader();
    if (current.isEmpty()) return; // A transient failure never reports a proxy change.
    if (current == watch->previous) return;
    watch->previous = current;
    emit changed();
}

ProxyChanges::~ProxyChanges() = default;
