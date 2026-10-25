#include "infrastructure/systemproxy/windows/proxyrecoverylock.h"
#include <QCryptographicHash>
#include <QScopeGuard>
#include <QString>
#include <vector>

WindowsProxyRecoveryLock::WindowsProxyRecoveryLock(WindowsProxyLockApi api) : api(api) {
    HANDLE token = nullptr;
    if (!api.openToken(GetCurrentProcess(),TOKEN_QUERY,&token) || !token) return;
    const auto closeToken=qScopeGuard([&]{api.close(token);});
    DWORD bytes=0;
    if (api.tokenInformation(token,TokenUser,nullptr,0,&bytes) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER
        || bytes<sizeof(TOKEN_USER) || bytes>65536) return;
    std::vector<TOKEN_USER> buffer((bytes+sizeof(TOKEN_USER)-1)/sizeof(TOKEN_USER));
    DWORD actual=bytes;
    if (!api.tokenInformation(token,TokenUser,buffer.data(),bytes,&actual)
        || actual<sizeof(TOKEN_USER) || actual>bytes || !buffer.front().User.Sid) return;
    LPWSTR identity=nullptr;
    if (!api.sidString(buffer.front().User.Sid,&identity) || !identity) return;
    const auto freeIdentity=qScopeGuard([&]{api.free(identity);});
    const auto sid=QString::fromWCharArray(identity);
    if (sid.isEmpty()) return;
    const auto hash=QCryptographicHash::hash(sid.toUtf8(),QCryptographicHash::Sha256).toHex();
    const auto name=QStringLiteral("Global\\JustConnect-proxy-recovery-")+QString::fromLatin1(hash);
    // A logon-token default DACL need not grant the same user access from another session.
    const DWORD access=SYNCHRONIZE|MUTEX_MODIFY_STATE;
    const auto permissions=QStringLiteral("D:P(A;;0x")+QString::number(access,16)+";;;"+sid+')';
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if (!api.descriptor(reinterpret_cast<LPCWSTR>(permissions.utf16()),SDDL_REVISION_1,&descriptor,nullptr) || !descriptor) return;
    const auto freeDescriptor=qScopeGuard([&]{api.free(descriptor);});
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};
    mutex=api.create(&security,reinterpret_cast<LPCWSTR>(name.utf16()),0,access);
    if (!mutex) return;
    const auto result=api.wait(mutex,0);
    owned=result==WAIT_OBJECT_0 || result==WAIT_ABANDONED;
}

WindowsProxyRecoveryLock::~WindowsProxyRecoveryLock() {
    if (owned) api.release(mutex);
    if (mutex) api.close(mutex);
}
