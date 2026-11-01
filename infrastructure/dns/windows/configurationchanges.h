#pragma once

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <initializer_list>
#include <utility>
#include <vector>

namespace WindowsDNS {
// DNS settings/policies and adapter changes invalidate the complete native read.
class Changes {
public:
    using Key = std::pair<HKEY, const wchar_t *>;
    explicit Changes(std::initializer_list<Key> keys = {
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\Dnscache"},
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\Tcpip"},
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies"}})
    {
        for (const auto &[root,path] : keys) {
            watches.push_back({});
            auto &watch = watches.back();
            watch.event = CreateEventW(nullptr,TRUE,FALSE,nullptr);
            if (!watch.event || RegOpenKeyExW(root,path,0,KEY_NOTIFY|KEY_WOW64_64KEY,&watch.key) != ERROR_SUCCESS
                || !arm(watch)) return;
        }
        network = CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if (!network || NotifyIpInterfaceChange(AF_UNSPEC,interfaceChanged,network,FALSE,&interfaces) != NO_ERROR
            || NotifyUnicastIpAddressChange(AF_UNSPEC,addressChanged,network,FALSE,&addresses) != NO_ERROR) return;
        watching = true;
    }
    Changes(const Changes &) = delete;
    Changes &operator=(const Changes &) = delete;
    ~Changes()
    {
        // Callbacks only signal the event; cancellation cannot wait on our reader lock.
        if (interfaces) CancelMibChangeNotify2(interfaces);
        if (addresses) CancelMibChangeNotify2(addresses);
        if (network) CloseHandle(network);
        for (const auto &watch : watches) {
            if (watch.key) RegCloseKey(watch.key);
            if (watch.event) CloseHandle(watch.event);
        }
    }
    bool available() const { return watching; }
    bool pending() const
    {
        if (!watching || WaitForSingleObject(network,0) != WAIT_TIMEOUT) return true;
        for (const auto &watch : watches)
            if (WaitForSingleObject(watch.event,0) != WAIT_TIMEOUT) return true;
        return false;
    }
    bool changed()
    {
        if (!watching) return true;
        bool changed = false;
        for (const auto &watch : watches) {
            const auto state = WaitForSingleObject(watch.event,0);
            if (state == WAIT_TIMEOUT) continue;
            changed = true;
            if (state != WAIT_OBJECT_0 || !ResetEvent(watch.event) || !arm(watch)) watching = false;
        }
        const auto state = WaitForSingleObject(network,0);
        if (state != WAIT_TIMEOUT) {
            changed = true;
            if (state != WAIT_OBJECT_0 || !ResetEvent(network)) watching = false;
        }
        return changed || !watching;
    }
private:
    struct Watch { HKEY key = nullptr; HANDLE event = nullptr; };
    static bool arm(const Watch &watch)
    {
        return RegNotifyChangeKeyValue(watch.key,TRUE,REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET
            |REG_NOTIFY_CHANGE_SECURITY|REG_NOTIFY_THREAD_AGNOSTIC,watch.event,TRUE) == ERROR_SUCCESS;
    }
    static void CALLBACK interfaceChanged(void *event,PMIB_IPINTERFACE_ROW,MIB_NOTIFICATION_TYPE) { SetEvent(event); }
    static void CALLBACK addressChanged(void *event,PMIB_UNICASTIPADDRESS_ROW,MIB_NOTIFICATION_TYPE) { SetEvent(event); }
    std::vector<Watch> watches;
    HANDLE network = nullptr, interfaces = nullptr, addresses = nullptr;
    bool watching = false;
};
}
