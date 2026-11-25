#pragma once
#include <QByteArray>
#include <QString>

enum class CredentialStatus { Success, NotFound, Locked, Unavailable, PermissionDenied, Cancelled, Limit, InvalidArgument, Failed, Conflict };
struct CredentialResult {
    CredentialStatus status = CredentialStatus::Failed;
    QByteArray value;
    qint64 nativeCode = 0;
    bool succeeded() const { return status==CredentialStatus::Success; }
};

class CredentialStore {
public:
    virtual ~CredentialStore() = default;
    virtual CredentialResult read(const QString &key) = 0;
    virtual CredentialResult write(const QString &key,const QByteArray &value) = 0;
    // Records that must survive a process restart (recovery journals) go through
    // this hook: backends whose plain write() may be memory-only (no usable
    // keyring) still guarantee durability here. The default is plain write().
    virtual CredentialResult writePersistent(const QString &key,const QByteArray &value) { return write(key,value); }
    virtual CredentialResult remove(const QString &key) = 0;
    static constexpr qsizetype MaxBytes = 65536;
    static bool validKey(const QString &key) {
        if (key.size()!=64) return false;
        for (auto c:key) if (!((c>='a' && c<='f') || (c>='0' && c<='9'))) return false;
        return true;
    }
};
