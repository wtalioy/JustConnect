#include "infrastructure/networkhelper/windows/session.h"
#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/packetrelay.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "infrastructure/tundevice/windows/recovery.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/dns/windows/dnscontract.h"
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
void originalDnsExclusions(const std::vector<WindowsNrptRedirect> &sources,const std::vector<WindowsTunPrefix> &captures)
{
    const auto allowed=[&](IN_ADDR value){
        for(const auto &prefix:captures){
            if(prefix.bits>32)fail("invalid original DNS capture length");
            const auto mask=prefix.bits?0xffffffffu<<(32-prefix.bits):0;
            if((ntohl(value.S_un.S_addr)&mask)==ntohl(prefix.address.S_un.S_addr))fail("original DNS endpoint overlaps campus capture");
        }
    };
    for(const auto &source:sources){
        allowed(source.server);
        for(const auto &server:source.servers()){
            IN_ADDR ipv4{};
            if(InetPtonW(AF_INET,server.c_str(),&ipv4)==1)allowed(ipv4);
        }
    }
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
    if(value.Size()!=6)fail("unknown device configuration fields");
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
    const auto originals=value.GetNamedArray(L"original_dns");
    if(originals.Size()>NetworkDnsDomainLimit)fail("too many original DNS providers");
    std::set<std::wstring> ids;
    for(const auto &item:originals){
        const auto source=item.GetObject();
        if(source.Size()!=3)fail("unknown original DNS source fields");
        const auto snapshot=source.GetNamedObject(L"source");
        if(snapshot.Size()!=8 || snapshot.GetNamedString(L"store")!=L"local"
            || snapshot.GetNamedNumber(L"version")!=WindowsDNS::NrptVersion || snapshot.GetNamedNumber(L"options")!=WindowsDNS::GenericServersOption
            || snapshot.GetNamedValue(L"owner").ValueType()!=JsonValueType::Null)fail("invalid original DNS source snapshot");
        const auto expectedClass=snapshot.GetNamedString(L"class"),original=snapshot.GetNamedString(L"servers");
        GUID expected{};
        if(FAILED(CLSIDFromString(snapshot.GetNamedString(L"id").c_str(),&expected)) || expected==GUID{})fail("invalid original DNS provider identity");
        std::vector<std::wstring> names,servers;
        for(const auto &name:snapshot.GetNamedArray(L"namespaces")){const auto value=name.GetString();names.emplace_back(value.data(),value.size());}
        for(const auto &server:source.GetNamedArray(L"servers")){const auto value=server.GetString();servers.emplace_back(value.data(),value.size());}
        auto entry=WindowsNrptRedirect::prepareSystem(names,servers,address(source.GetNamedString(L"listen")));
        if(entry.id!=expected || entry.policyClass!=std::wstring(expectedClass.data(),expectedClass.size())
            || entry.original!=std::wstring(original.data(),original.size()) || entry.namespaces!=names)
            fail("original DNS source identity or values changed before activation");
        wchar_t key[39]{};if(!StringFromGUID2(entry.id,key,39) || !ids.insert(key).second)fail("duplicate original DNS provider");
        result.originalDNS.push_back(std::move(entry));
    }
    originalDnsExclusions(result.originalDNS,result.captures);
    return result;
}catch(const winrt::hresult_error &){fail("invalid native device configuration JSON");}

std::unique_ptr<WindowsNetworkSession> WindowsNetworkSession::apply(const std::wstring &driver,const GUID &owner,
    const WindowsProcess &caller,const WindowsNetworkConfiguration &configuration,WindowsPacketPipe &control)
{
    const auto started=GetTickCount64();
    WindowsNetworkLock lock;
    WindowsTunDevice::validate(configuration.source,configuration.peer,configuration.mtu,configuration.captures);
    if(configuration.dns && (!configuration.dns->valid() || configuration.dns->server.S_un.S_addr!=configuration.peer.S_un.S_addr))fail("DNS is not owned by the private device");
    auto session=std::unique_ptr<WindowsNetworkSession>(new WindowsNetworkSession);
    auto &record=session->record;
    record.owner=owner;record.caller=caller.identity();record.dns=configuration.dns;record.originalDNS=configuration.originalDNS;
    originalDnsExclusions(record.originalDNS,configuration.captures);
    WindowsProcess current(GetCurrentProcessId());record.helper=current.identity();
    if(FAILED(CoCreateGuid(&record.adapter)))fail("allocate owned adapter identity");
    session->recovery.declare(record);session->declared=true;
    const auto declared=GetTickCount64();
    session->device=WindowsTunDevice::create(driver,record.adapter,configuration.source,configuration.peer,configuration.mtu,configuration.captures,
        [&](const auto &identity){if(identity.guid!=record.adapter)fail("adapter departed from write-ahead ownership");});
    const auto configured=GetTickCount64();
    WindowsDNS::applySystem(record.dns,record.originalDNS);
    session->setupTimes={declared-started,configured-declared,GetTickCount64()-configured};
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
void WindowsNetworkSession::reconcile(const std::vector<WindowsTunPrefix> &captures,bool refreshDNS)
{
    if(quiet || restored)fail("network session is no longer capturing",ERROR_OPERATION_ABORTED);
    originalDnsExclusions(record.originalDNS,captures);
    device->reconcile(captures);
    if(refreshDNS)WindowsDNS::refreshCache();
}
void WindowsNetworkSession::quiesce()
{
    if(restored || quiet)return;
    // Keep the device/pipe alive until the ordinary core stops after capture release.
    recovery.beginOwnedRestore(record.owner);
    device->reconcile({});recovery.restoreOriginalDNS(record.owner);quiet=true;
}
void WindowsNetworkSession::restore()
{
    if(!declared || restored)return;
    try{
        if(!recovery.restoreOwned(record.owner,[&]{stopData();finishWindowsAdapterClose(record.adapter);}))fail("owned device release remains pending",ERROR_TIMEOUT);
        restored=true;
    }catch(...){stopData();throw;}
}
WindowsNetworkSession::~WindowsNetworkSession()
{
    try{restore();}catch(...){stopData();}
}
