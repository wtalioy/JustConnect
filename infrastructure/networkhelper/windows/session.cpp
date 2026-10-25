#include "infrastructure/networkhelper/windows/session.h"
#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/packetrelay.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/tundevice/windows/recovery.h"
#include "windowsnetworkcontract.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <charconv>
#include <set>
#include <system_error>

using namespace winrt::Windows::Data::Json;
namespace {
[[noreturn]] void fail(const char *stage,DWORD code=ERROR_INVALID_DATA){throw std::system_error(code,std::system_category(),stage);}
IN_ADDR address(const winrt::hstring &text){
    IN_ADDR result{};wchar_t canonical[INET_ADDRSTRLEN]{};
    if(InetPtonW(AF_INET,text.c_str(),&result)!=1 || !InetNtopW(AF_INET,&result,canonical,INET_ADDRSTRLEN) || text!=canonical)fail("noncanonical device IPv4 address");
    return result;
}
}
std::vector<WindowsTunPrefix> decodeWindowsCapturePrefixes(const std::string &message) try
{
    if(message.empty() || message.size()>WindowsNetworkContract::MaxMessageBytes)fail("invalid device configuration size");
    const auto value=JsonArray::Parse(winrt::to_hstring(message));
    std::vector<WindowsTunPrefix> result;
    std::set<std::string> seen;
    for(const auto &item:value){
        const auto text=winrt::to_string(item.GetString());const auto slash=text.find('/');
        if(slash==std::string::npos || !seen.insert(text).second)fail("invalid or duplicate capture prefix");
        const auto number=text.substr(slash+1);unsigned int bits=0;
        const auto parsed=std::from_chars(number.data(),number.data()+number.size(),bits);
        if(parsed.ec!=std::errc{} || parsed.ptr!=number.data()+number.size() || bits>32 || std::to_string(bits)!=number)fail("noncanonical capture length");
        result.push_back({address(winrt::to_hstring(text.substr(0,slash))),static_cast<unsigned char>(bits)});
    }
    return result;
}catch(const winrt::hresult_error &){fail("invalid native capture JSON");}
WindowsNetworkConfiguration decodeWindowsNetworkConfiguration(const std::string &message) try
{
    if(message.empty() || message.size()>WindowsNetworkContract::MaxMessageBytes)fail("invalid device configuration size");
    const auto value=JsonObject::Parse(winrt::to_hstring(message));
    if(value.Size()!=5)fail("unknown device configuration fields");
    WindowsNetworkConfiguration result;
    result.source=address(value.GetNamedString(L"address"));result.peer=address(value.GetNamedString(L"peer"));
    const auto mtu=value.GetNamedNumber(L"mtu");
    if(!(mtu>=68 && mtu<=65535) || mtu!=static_cast<unsigned int>(mtu))fail("invalid device MTU");
    result.mtu=static_cast<unsigned int>(mtu);
    result.captures=decodeWindowsCapturePrefixes(winrt::to_string(value.GetNamedArray(L"capture_prefixes").Stringify()));
    WindowsTunDevice::validate(result.source,result.peer,result.mtu,result.captures);
    std::vector<std::wstring> domains;
    for(const auto &item:value.GetNamedArray(L"dns_domains")){const auto name=item.GetString();domains.emplace_back(name.data(),name.size());}
    if(!domains.empty())result.dns=WindowsDnsRule::create(domains,result.peer);
    return result;
}catch(const winrt::hresult_error &){fail("invalid native device configuration JSON");}

std::unique_ptr<WindowsNetworkSession> WindowsNetworkSession::apply(const std::wstring &driver,const GUID &owner,
    const WindowsProcess &caller,const WindowsNetworkConfiguration &configuration,WindowsPacketPipe &control)
{
    WindowsTunDevice::validate(configuration.source,configuration.peer,configuration.mtu,configuration.captures);
    if(configuration.dns && (!configuration.dns->valid() || configuration.dns->server.S_un.S_addr!=configuration.peer.S_un.S_addr))fail("DNS is not owned by the private device");
    auto session=std::unique_ptr<WindowsNetworkSession>(new WindowsNetworkSession);
    auto &record=session->record;
    record.owner=owner;record.caller=caller.identity();record.dns=configuration.dns;
    WindowsProcess current(GetCurrentProcessId());record.helper=current.identity();
    if(FAILED(CoCreateGuid(&record.adapter)))fail("allocate owned adapter identity");
    session->recovery.declare(record);session->declared=true;
    session->device=WindowsTunDevice::create(driver,record.adapter,configuration.source,configuration.peer,configuration.mtu,configuration.captures,
        [&](const auto &identity){if(identity.guid!=record.adapter)fail("adapter departed from write-ahead ownership");});
    if(record.dns)record.dns->applySystem();
    session->packets=WindowsPacketPipe::create(windowsPacketPipeName(owner),caller);
    auto *active=session.get();
    session->relay=std::thread([active,&caller,&control,mtu=configuration.mtu]{
        try{
            active->packets->accept(caller,WindowsNetworkContract::ControlTimeoutMs);
            relayWindowsPackets(*active->device,*active->packets,mtu);
        }catch(...){}
        if(!active->quiet && !active->stopping)control.close();
    });
    return session;
}
void WindowsNetworkSession::stopData()
{
    stopping=true;
    if(packets)packets->close();
    if(device)device->close();
    if(relay.joinable())relay.join();
}
void WindowsNetworkSession::reconcile(const std::vector<WindowsTunPrefix> &captures)
{
    if(quiet || restored)fail("network session is no longer capturing",ERROR_OPERATION_ABORTED);
    device->reconcile(captures);
}
void WindowsNetworkSession::quiesce()
{
    if(restored || quiet)return;
    // Keep the device/pipe alive until the ordinary core stops after capture release.
    recovery.beginOwnedRestore(record.owner);
    device->reconcile({});quiet=true;
}
void WindowsNetworkSession::restore()
{
    if(!declared || restored)return;
    try{
        if(!recovery.restoreOwned(record.owner,[&]{stopData();restoreWindowsAdapter(record.adapter);}))fail("owned device release remains pending",ERROR_TIMEOUT);
        restored=true;
    }catch(...){stopData();throw;}
}
WindowsNetworkSession::~WindowsNetworkSession()
{
    try{restore();}catch(...){stopData();}
}
