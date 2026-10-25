#pragma once

#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/process/windows/identity.h"
#include "infrastructure/networkjournal/windows/registry.h"
#include <optional>

enum class WindowsRecoveryPhase { Declared, Restoring, Restored };
struct WindowsNetworkRecord {
    GUID owner{},adapter{};
    WindowsProcessIdentity caller,helper;
    std::optional<WindowsDnsRule> dns;
    WindowsRecoveryPhase phase = WindowsRecoveryPhase::Declared;
};

std::string encodeWindowsNetworkRecord(const WindowsNetworkRecord &record);
WindowsNetworkRecord decodeWindowsNetworkRecord(const std::string &data);

// The service and active helper serialize every checkpoint and recovery under the same machine lock.
class WindowsNetworkLock final {
public:
    WindowsNetworkLock();
    ~WindowsNetworkLock();
    WindowsNetworkLock(const WindowsNetworkLock &) = delete;
    WindowsNetworkLock &operator=(const WindowsNetworkLock &) = delete;
private:
    HANDLE mutex = nullptr;
};

class WindowsNetworkRecovery final {
public:
    void declare(const WindowsNetworkRecord &record);
    WindowsNetworkRecord read(const GUID &owner);
    std::vector<GUID> owners();
    // A live helper keeps authority; recovery never competes with its mutations.
    bool restoreAbandoned(const GUID &owner,const std::wstring &callerSid={});
    void acknowledge(const GUID &owner,const std::wstring &callerSid);
private:
    WindowsRegistryJournal journal;
};
