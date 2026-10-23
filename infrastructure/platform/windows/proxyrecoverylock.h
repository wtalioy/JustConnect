#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

struct WindowsProxyLockApi {
    decltype(&OpenProcessToken) openToken = &OpenProcessToken;
    decltype(&GetTokenInformation) tokenInformation = &GetTokenInformation;
    decltype(&ConvertSidToStringSidW) sidString = &ConvertSidToStringSidW;
    decltype(&ConvertStringSecurityDescriptorToSecurityDescriptorW) descriptor = &ConvertStringSecurityDescriptorToSecurityDescriptorW;
    decltype(&CreateMutexExW) create = &CreateMutexExW;
    decltype(&WaitForSingleObject) wait = &WaitForSingleObject;
    decltype(&ReleaseMutex) release = &ReleaseMutex;
    decltype(&CloseHandle) close = &CloseHandle;
    decltype(&LocalFree) free = &LocalFree;
};

// Construct and destroy on the recovery worker thread; ownership is independent of data/temp roots.
class WindowsProxyRecoveryLock {
public:
    explicit WindowsProxyRecoveryLock(WindowsProxyLockApi api = {});
    ~WindowsProxyRecoveryLock();
    WindowsProxyRecoveryLock(const WindowsProxyRecoveryLock &) = delete;
    WindowsProxyRecoveryLock &operator=(const WindowsProxyRecoveryLock &) = delete;
    bool isLocked() const { return owned; }
private:
    const WindowsProxyLockApi api;
    HANDLE mutex = nullptr;
    bool owned = false;
};
