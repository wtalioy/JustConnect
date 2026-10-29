#pragma once

#include "infrastructure/dns/windows/nrpt.h"
#include "infrastructure/process/windows/identity.h"
#include "infrastructure/networkjournal/windows/registry.h"
#include <optional>
#include <functional>

enum class WindowsRecoveryPhase { Declared, Restoring, Restored };
struct WindowsNetworkRecord {
    GUID owner{},adapter{};
    WindowsProcessIdentity caller,helper;
    std::optional<WindowsDnsRule> dns;
    WindowsRecoveryPhase phase = WindowsRecoveryPhase::Declared;
    std::vector<WindowsNrptRedirect> originalDNS;
};

std::string encodeWindowsNetworkRecord(const WindowsNetworkRecord &record);
WindowsNetworkRecord decodeWindowsNetworkRecord(const std::string &data);
std::string encodeWindowsNrptRedirect(const WindowsNrptRedirect &value);
WindowsNrptRedirect decodeWindowsNrptRedirect(const std::string &data);

// The service and active helper serialize every checkpoint and recovery under the same machine lock.
class WindowsNetworkLock final {
public:
    enum class Scope { Network, ServiceInstallation };
    explicit WindowsNetworkLock(Scope scope = Scope::Network);
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
    // A live owner first releases DNS, then its private device, before publishing a durable receipt.
    bool restoreOwned(const GUID &owner,const std::function<void()> &release);
    void beginOwnedRestore(const GUID &owner);
    void restoreOriginalDNS(const GUID &owner);
    void acknowledge(const GUID &owner,const std::wstring &callerSid);
private:
    bool restoreRecord(WindowsNetworkRecord &record,const std::function<void()> &release);
    WindowsNetworkRecord ownedRecord(const GUID &owner);
    void beginRestore(WindowsNetworkRecord &record);
    void restoreCampusDNS(WindowsNetworkRecord &record);
    void restoreOriginalDNS(WindowsNetworkRecord &record);
    WindowsRegistryJournal journal;
};
