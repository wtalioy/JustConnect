#include "infrastructure/platform/systemcredentialstore.h"
#include <windows.h>
#include <wincred.h>

namespace {
CredentialStatus status(DWORD error) {
    switch(error) {
    case ERROR_NOT_FOUND: return CredentialStatus::NotFound;
    case ERROR_ACCESS_DENIED: return CredentialStatus::PermissionDenied;
    case ERROR_CANCELLED: return CredentialStatus::Cancelled;
    case ERROR_NO_SUCH_LOGON_SESSION: case ERROR_NOT_SUPPORTED: case ERROR_SERVICE_NOT_ACTIVE: return CredentialStatus::Unavailable;
    default: return CredentialStatus::Failed;
    }
}
QString target(const QString &key) { return "JustConnect/credentials/v1/"+key; }
CredentialResult failure() {const auto code=GetLastError();return {status(code),{},code};}
class Store final : public CredentialStore {
public:
    CredentialResult read(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        const auto name=target(key); PCREDENTIALW entry=nullptr;
        if (!CredReadW(reinterpret_cast<LPCWSTR>(name.utf16()),CRED_TYPE_GENERIC,0,&entry)) return failure();
        const QByteArray value(reinterpret_cast<const char *>(entry->CredentialBlob),entry->CredentialBlobSize);
        SecureZeroMemory(entry->CredentialBlob,entry->CredentialBlobSize);
        CredFree(entry);
        return {CredentialStatus::Success,value};
    }
    CredentialResult write(const QString &key,const QByteArray &value) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        if (value.size()>CRED_MAX_CREDENTIAL_BLOB_SIZE) return {CredentialStatus::Limit,{}};
        const auto name=target(key); CREDENTIALW entry{};
        entry.Type=CRED_TYPE_GENERIC; entry.TargetName=const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(name.utf16()));
        entry.CredentialBlobSize=DWORD(value.size()); entry.CredentialBlob=reinterpret_cast<LPBYTE>(const_cast<char *>(value.constData()));
        entry.Persist=CRED_PERSIST_LOCAL_MACHINE;
        if (!CredWriteW(&entry,0)) return failure();
        return {CredentialStatus::Success,{}};
    }
    CredentialResult remove(const QString &key) override {
        if (!validKey(key)) return {CredentialStatus::InvalidArgument,{}};
        const auto name=target(key);
        if (CredDeleteW(reinterpret_cast<LPCWSTR>(name.utf16()),CRED_TYPE_GENERIC,0)) return {CredentialStatus::Success,{}};
        return failure();
    }
};
}
std::unique_ptr<CredentialStore> createSystemCredentialStore() { return std::make_unique<Store>(); }
