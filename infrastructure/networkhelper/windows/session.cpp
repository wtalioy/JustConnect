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
#include <iostream>
#include <utility>
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
std::vector<WindowsTunPrefix> decodeWindowsCapturePrefixes(const JsonArray &value) try
{
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
WindowsNetworkConfiguration decodeWindowsNetworkConfiguration(const JsonObject &value) try
{
    if(value.Size()!=6)fail("unknown device configuration fields");
    WindowsNetworkConfiguration result;
    result.source=address(value.GetNamedString(L"address"));result.peer=address(value.GetNamedString(L"peer"));
    const auto mtu=value.GetNamedNumber(L"mtu");
    if(!(mtu>=68 && mtu<=65535) || mtu!=static_cast<unsigned int>(mtu))fail("invalid device MTU");
    result.mtu=static_cast<unsigned int>(mtu);
    result.captures=decodeWindowsCapturePrefixes(value.GetNamedArray(L"capture_prefixes"));
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
    session->startData(caller,control,configuration.mtu);
    return session;
}
void WindowsNetworkSession::startData(const WindowsProcess &caller,WindowsPacketPipe &control,unsigned int mtu)
{
    stopping=false;quiet=false;
    packets=WindowsPacketPipe::create(windowsPacketPipeName(record.owner),caller);
    relay=std::thread([this,&caller,&control,mtu]{
        try{
            packets->accept(caller,WindowsNetworkContract::ControlTimeoutMs);
            relayWindowsPackets(*device,*packets,mtu);
        }catch(...){}
        if(!quiet && !stopping)control.close();
    });
}
void WindowsNetworkSession::stopData(bool retainAdapter)
{
    stopping=true;
    if(packets)packets->close();
    std::exception_ptr failure;
    try{if(device){if(retainAdapter)device->deactivate();else device->close();}}catch(...){failure=std::current_exception();}
    if(relay.joinable())relay.join();
    packets.reset();
    if(failure)std::rethrow_exception(failure);
}
void WindowsNetworkSession::park()
{
    if(!declared || restored || parked)return;
    try{
        recovery.parkOwned(record.owner,[&]{stopData(true);});
        record=recovery.read(record.owner);parked=true;
    }catch(const std::exception &error){
        std::cerr<<"discarding unavailable idle adapter: "<<error.what()<<'\n';
        restore();
    }
}
void WindowsNetworkSession::resume(const WindowsProcess &caller,const WindowsNetworkConfiguration &configuration,WindowsPacketPipe &control)
{
    if(!hasCachedDevice())fail("network session has no idle adapter",ERROR_INVALID_STATE);
    WindowsNetworkLock lock;
    WindowsTunDevice::validate(configuration.source,configuration.peer,configuration.mtu,configuration.captures);
    if(configuration.dns && (!configuration.dns->valid() || configuration.dns->server.S_un.S_addr!=configuration.peer.S_un.S_addr))fail("DNS is not owned by the private device");
    originalDnsExclusions(configuration.originalDNS,configuration.captures);
    auto next=record;next.caller=caller.identity();next.dns=configuration.dns;next.originalDNS=configuration.originalDNS;next.phase=WindowsRecoveryPhase::Declared;
    const auto started=GetTickCount64();recovery.resumeOwned(next);record=std::move(next);parked=false;
    const auto declaredAt=GetTickCount64();
    device->activate(configuration.source,configuration.peer,configuration.mtu,configuration.captures);
    const auto configured=GetTickCount64();WindowsDNS::applySystem(record.dns,record.originalDNS);
    setupTimes={declaredAt-started,configured-declaredAt,GetTickCount64()-configured};
    startData(caller,control,configuration.mtu);
}
void WindowsNetworkSession::reconcile(const std::vector<WindowsTunPrefix> &captures,bool refreshDNS)
{
    if(quiet || restored || parked)fail("network session is no longer capturing",ERROR_OPERATION_ABORTED);
    originalDnsExclusions(record.originalDNS,captures);
    device->reconcile(captures);
    if(refreshDNS)WindowsDNS::refreshCache();
}
void WindowsNetworkSession::quiesce()
{
    if(restored || parked || quiet)return;
    // Keep the device/pipe alive until the ordinary core stops after capture release.
    recovery.beginOwnedRestore(record.owner);
    device->reconcile({});recovery.restoreOriginalDNS(record.owner);quiet=true;
}
void WindowsNetworkSession::restore()
{
    if(!declared || restored)return;
    try{
        if(!recovery.restoreOwned(record.owner,[&]{stopData();finishWindowsAdapterClose(record.adapter);}))fail("owned device release remains pending",ERROR_TIMEOUT);
        restored=true;parked=false;
    }catch(...){stopData();throw;}
}
WindowsNetworkSession::~WindowsNetworkSession()
{
    const bool cached=parked;
    try{
        restore();
        if(cached)recovery.acknowledge(record.owner,record.caller.sid);
    }catch(...){stopData();}
}
