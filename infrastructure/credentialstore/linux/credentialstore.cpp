#include "infrastructure/credentialstore/systemcredentialstore.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QLibrary>
#include <QMutex>
#include <QSaveFile>
#include <QScopeGuard>
#include <QStandardPaths>

// libsecret is an optional runtime dependency: the store binds to libsecret-1.so.0 when present.
// The keyring is the only persistent credential store. When the system keyring is unavailable —
// libsecret missing, no secret service, or a transient failure — sign-in still works for the
// current session, with secrets held in process memory only and never written to a plain file.
// Records that must survive a restart (recovery journals) go through writePersistent(), the one
// path allowed to keep a 0600 file. A locked or policy-denied keyring is the exception: those
// states are temporary, and secrets must not be silently diverted to weaker storage that the
// keyring could no longer supersede. Files written by earlier releases stay readable until the
// keyring accepts the same key again. Payloads are base64 so embedded NUL bytes survive.
namespace {

struct GErrorMirror { unsigned domain; int code; char *message; };
struct SecretSchemaAttribute { const char *name; int type; };
struct SecretSchemaMirror { const char *name; int flags; SecretSchemaAttribute attributes[32]; };

using StoreFn = int (*)(const SecretSchemaMirror *, const char *, const char *, const char *, void *, GErrorMirror **, const char *, const char *, ...);
using LookupFn = char *(*)(const SecretSchemaMirror *, void *, GErrorMirror **, const char *, const char *, ...);
using ClearFn = int (*)(const SecretSchemaMirror *, void *, GErrorMirror **, const char *, const char *, ...);
using QuarkFn = unsigned (*)(void);
using FreeFn = void (*)(void *);

// SecretError values (libsecret secret-types.h) mapped onto shared credential statuses.
constexpr int SecretErrorLocked = 2, SecretErrorNoSuchObject = 3, SecretErrorAlreadyExists = 4;

const char *const SecretLibrary = "libsecret-1.so.0";
const char *const GlibLibrary = "libglib-2.0.so.0";
const char *const SchemaName = "com.github.wtalioy.JustConnect.Credential";
const char *const SecretLabel = "JustConnect Saved Data";
const char *const ServiceAttribute = "JustConnect";
constexpr int SchemaDontMatchName = 1, AttributeString = 0;

class FileStore {
public:
    static QString path(const QString &key) {
        const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        return directory.isEmpty() ? QString() : directory + "/credentials/v1/" + key;
    }
    static CredentialResult read(const QString &key) {
        const auto file = path(key);
        if (file.isEmpty()) return {CredentialStatus::Unavailable, {}};
        QFile input(file);
        if (!input.open(QIODevice::ReadOnly)) return {CredentialStatus::NotFound, {}};
        return {CredentialStatus::Success, input.readAll()};
    }
    static CredentialResult write(const QString &key, const QByteArray &value) {
        const auto file = path(key);
        if (file.isEmpty()) return {CredentialStatus::Unavailable, {}};
        if (!QDir().mkpath(QFileInfo(file).absolutePath())) return {CredentialStatus::Failed, {}};
        QSaveFile output(file);
        if (!output.open(QIODevice::WriteOnly) || output.write(value) != value.size() || !output.commit())
            return {QFile::exists(file) ? CredentialStatus::Failed : CredentialStatus::PermissionDenied, {}};
        // The journal fallback is deliberately weaker storage, so keep it strictly owner-only.
        QFile::setPermissions(file, QFile::Permissions(int(QFile::ReadOwner) | int(QFile::WriteOwner)));
        return {CredentialStatus::Success, {}};
    }
    static bool remove(const QString &key) {
        const auto file = path(key);
        return !file.isEmpty() && QFile::exists(file) && QFile::remove(file);
    }
};

class Store final : public CredentialStore {
public:
    Store() {
        library.setFileName(SecretLibrary);
        library.setLoadHints(QLibrary::ResolveAllSymbolsHint);
        if (!library.load()) return;
        store = reinterpret_cast<StoreFn>(library.resolve("secret_password_store_sync"));
        lookup = reinterpret_cast<LookupFn>(library.resolve("secret_password_lookup_sync"));
        clear = reinterpret_cast<ClearFn>(library.resolve("secret_password_clear_sync"));
        // The exported getter is secret_error_get_quark; secret_error_quark is
        // the internal G_DEFINE_QUARK helper and is absent from the symbol table.
        quark = reinterpret_cast<QuarkFn>(library.resolve("secret_error_get_quark"));
        glib.setFileName(GlibLibrary);
        if (store && lookup && clear && quark && glib.load()) {
            errorFree = reinterpret_cast<void (*)(GErrorMirror *)>(glib.resolve("g_error_free"));
            gfree = reinterpret_cast<FreeFn>(glib.resolve("g_free"));
            if (errorFree && gfree) {
                schema.name = SchemaName;
                schema.flags = SchemaDontMatchName; // Tolerate service-side schema name changes.
                schema.attributes[0] = {"service", AttributeString};
                schema.attributes[1] = {"account", AttributeString};
                schema.attributes[2] = {nullptr, AttributeString};
                secretDomain = quark();
            }
        }
    }
    CredentialResult read(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument, {}};
        if (!available()) {
            QMutexLocker guard(&mutex);
            const auto cached = session.constFind(key);
            if (cached != session.constEnd()) return {CredentialStatus::Success, *cached};
            return FileStore::read(key);
        }
        QMutexLocker guard(&mutex);
        GErrorMirror *error = nullptr;
        char *text = lookup(&schema, nullptr, &error, "service", ServiceAttribute,
            "account", key.toUtf8().constData(), static_cast<const char *>(nullptr));
        if (text) {
            const auto encoded = QByteArray(text);
            gfree(text);
            const auto release = qScopeGuard([&] { if (error) errorFree(error); });
            if (!encoded.startsWith("b64:")) return {CredentialStatus::Failed, {}};
            session.remove(key); // The keyring is authoritative again.
            return {CredentialStatus::Success, QByteArray::fromBase64(encoded.mid(4))};
        }
        const auto mapped = mapError(error);
        const auto release = qScopeGuard([&] { if (error) errorFree(error); });
        // Refusing states pass the keyring's answer through; weaker copies stay
        // hidden while the keyring is locked or denies access.
        if (mapped == CredentialStatus::Locked || mapped == CredentialStatus::Cancelled
            || mapped == CredentialStatus::PermissionDenied)
            return {mapped, {}, error ? qint64(error->code) : 0};
        const auto cached = session.constFind(key);
        if (cached != session.constEnd()) return {CredentialStatus::Success, *cached};
        // Files written by earlier releases remain readable while the keyring is authoritative.
        const auto fallback = FileStore::read(key);
        if (fallback.succeeded()) return fallback;
        // Missing keys and unreachable keyrings both read as "nothing saved",
        // keeping sign-in usable on systems without a secret service.
        return {CredentialStatus::NotFound, {}};
    }
    CredentialResult write(const QString &key, const QByteArray &value) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument, {}};
        if (value.size() > MaxBytes) return {CredentialStatus::Limit, {}};
        if (!available()) {
            QMutexLocker guard(&mutex);
            session.insert(key, value);
            return {CredentialStatus::Success, {}};
        }
        QMutexLocker guard(&mutex);
        const auto stored = keyringWrite(key, value);
        if (stored.succeeded()) {
            session.remove(key);
            FileStore::remove(key); // Drop any file copy from an earlier release.
            return stored;
        }
        // A locked or denied keyring must not silently divert secrets into weaker storage.
        if (stored.status == CredentialStatus::Locked || stored.status == CredentialStatus::Cancelled
            || stored.status == CredentialStatus::PermissionDenied)
            return stored;
        // No usable keyring (absent service or transient failure): sign-in still works for
        // the current session, in process memory only — credentials and tokens are never
        // written to a plain file. Restart-durable records go through writePersistent().
        session.insert(key, value);
        return {CredentialStatus::Success, {}};
    }
    CredentialResult writePersistent(const QString &key, const QByteArray &value) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument, {}};
        if (value.size() > MaxBytes) return {CredentialStatus::Limit, {}};
        if (!available()) {
            // Recovery journals must survive a restart even without a keyring;
            // this is the one sanctioned 0600-file path.
            return FileStore::write(key, value);
        }
        QMutexLocker guard(&mutex);
        const auto stored = keyringWrite(key, value);
        if (stored.succeeded()) {
            session.remove(key);
            FileStore::remove(key);
            return stored;
        }
        if (stored.status == CredentialStatus::Locked || stored.status == CredentialStatus::Cancelled
            || stored.status == CredentialStatus::PermissionDenied)
            return stored;
        // Degraded keyring: journals keep their durable 0600-file copy.
        return FileStore::write(key, value);
    }
    CredentialResult remove(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument, {}};
        QMutexLocker guard(&mutex);
        const auto sessionRemoved = session.remove(key);
        if (!available()) return (sessionRemoved || FileStore::remove(key)) ? CredentialResult{CredentialStatus::Success, {}}
            : CredentialResult{CredentialStatus::NotFound, {}};
        GErrorMirror *error = nullptr;
        char *present = lookup(&schema, nullptr, &error, "service", ServiceAttribute,
            "account", key.toUtf8().constData(), static_cast<const char *>(nullptr));
        if (present) {
            const auto release = qScopeGuard([&] { gfree(present); if (error) errorFree(error); });
            GErrorMirror *clearError = nullptr;
            const auto cleared = clear(&schema, nullptr, &clearError, "service", ServiceAttribute,
                "account", key.toUtf8().constData(), static_cast<const char *>(nullptr));
            const auto releaseClear = qScopeGuard([&] { if (clearError) errorFree(clearError); });
            FileStore::remove(key);
            if (!cleared) return {mapError(clearError), {}, clearError ? qint64(clearError->code) : 0};
            return {CredentialStatus::Success, {}};
        }
        const auto mapped = mapError(error);
        const auto release = qScopeGuard([&] { if (error) errorFree(error); });
        // The key may have lived only in this session's memory (no usable
        // keyring) or in the file copy of an earlier release.
        if (sessionRemoved || FileStore::remove(key)) return {CredentialStatus::Success, {}};
        // Repeat deletion reports absence even when the keyring itself is unreachable.
        if (mapped != CredentialStatus::NotFound && mapped != CredentialStatus::Failed)
            return {mapped, {}, error ? qint64(error->code) : 0};
        return {CredentialStatus::NotFound, {}};
    }
private:
    // Store into the keyring when usable; callers decide the weaker-storage
    // policy for the mapped refusal and unavailability outcomes. The mutex must
    // be held.
    CredentialResult keyringWrite(const QString &key, const QByteArray &value) {
        GErrorMirror *error = nullptr;
        const auto encoded = QByteArray("b64:" + value.toBase64());
        const auto stored = store(&schema, nullptr, SecretLabel, encoded.constData(), nullptr, &error,
            "service", ServiceAttribute, "account", key.toUtf8().constData(), static_cast<const char *>(nullptr));
        const auto release = qScopeGuard([&] { if (error) errorFree(error); });
        if (stored) return {CredentialStatus::Success, {}};
        const auto mapped = mapError(error);
        return {mapped, {}, error ? qint64(error->code) : 0};
    }
    bool available() const { return schema.name && secretDomain; }
    CredentialStatus mapError(const GErrorMirror *error) const {
        if (!error) return CredentialStatus::NotFound;
        if (error->domain == secretDomain) {
            switch (error->code) {
            case SecretErrorLocked: return CredentialStatus::Locked;
            case SecretErrorNoSuchObject: return CredentialStatus::NotFound;
            case SecretErrorAlreadyExists: return CredentialStatus::Conflict;
            default: return CredentialStatus::Failed;
            }
        }
        return CredentialStatus::Failed;
    }
    QMutex mutex;
    // Secrets from this session when the keyring could not store them; never
    // spilled to disk, never visible to other processes.
    QHash<QString, QByteArray> session;
    QLibrary library, glib;
    StoreFn store = nullptr;
    LookupFn lookup = nullptr;
    ClearFn clear = nullptr;
    QuarkFn quark = nullptr;
    void (*errorFree)(GErrorMirror *) = nullptr;
    FreeFn gfree = nullptr;
    SecretSchemaMirror schema{};
    unsigned secretDomain = 0;
};
}

std::unique_ptr<CredentialStore> createSystemCredentialStore() { return std::make_unique<Store>(); }
