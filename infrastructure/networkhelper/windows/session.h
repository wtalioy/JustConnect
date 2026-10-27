#pragma once
#include "infrastructure/tundevice/windows/adapter.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include <atomic>
#include <thread>

class WindowsPacketPipe;
struct WindowsNetworkConfiguration {
    IN_ADDR source{},peer{};
    unsigned int mtu=0;
    std::vector<WindowsTunPrefix> captures;
    std::optional<WindowsDnsRule> dns;
    std::vector<WindowsNrptRedirect> originalDNS;
};
WindowsNetworkConfiguration decodeWindowsNetworkConfiguration(const std::string &message);
std::vector<WindowsTunPrefix> decodeWindowsCapturePrefixes(const std::string &message);

class WindowsNetworkSession final {
public:
    static std::unique_ptr<WindowsNetworkSession> apply(const std::wstring &driver,const GUID &owner,
        const WindowsProcess &caller,const WindowsNetworkConfiguration &configuration,WindowsPacketPipe &control);
    ~WindowsNetworkSession();
    WindowsNetworkSession(const WindowsNetworkSession &)=delete;
    WindowsNetworkSession &operator=(const WindowsNetworkSession &)=delete;
    const WindowsTunIdentity &identity() const{return device->identity();}
    void reconcile(const std::vector<WindowsTunPrefix> &captures,bool refreshDNS=false);
    void quiesce();
    void restore();
    bool isRestored() const{return restored;}
private:
    WindowsNetworkSession()=default;
    void stopData();
    WindowsNetworkRecovery recovery;
    WindowsNetworkRecord record;
    std::unique_ptr<WindowsTunDevice> device;
    std::unique_ptr<WindowsPacketPipe> packets;
    std::thread relay;
    std::atomic<bool> quiet{false},stopping{false};
    bool declared=false,restored=false;
};
