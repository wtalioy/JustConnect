#include "infrastructure/networkhelper/windows/recovery.h"
#include "infrastructure/tundevice/windows/adapter.h"
#include "infrastructure/tundevice/windows/recovery.h"
#include "windowsnetworkcontract.h"
#include "ordinarytoken.h"
#include <ws2tcpip.h>
#include <sddl.h>
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <iostream>
#include <memory>
#include <system_error>
#include <cwctype>

namespace {
void check(bool value,const char *stage) { if (!value) throw std::runtime_error(stage); }
struct Handle { HANDLE value=nullptr;~Handle(){if(value)CloseHandle(value);} };
struct Key { HKEY value=nullptr;~Key(){if(value)RegCloseKey(value);} };
struct Service {SC_HANDLE value=nullptr;~Service(){if(value)CloseServiceHandle(value);}};
GUID uuid() { GUID value{};check(SUCCEEDED(CoCreateGuid(&value)),"allocate fixture UUID");return value; }
std::wstring guid(const GUID &value) {wchar_t text[39]{};check(StringFromGUID2(value,text,39)!=0,"format fixture UUID");return text;}
IN_ADDR address(const wchar_t *text) {IN_ADDR result{};check(InetPtonW(AF_INET,text,&result)==1,"parse fixture IPv4");return result;}
template<typename F> void refused(F operation,const char *stage)
{
    bool denied=false;
    try {operation();} catch(const std::system_error &){denied=true;}
    check(denied,stage);
}
std::wstring readyName(const GUID &owner) {return L"Local\\JustConnectRecoveryFixture-"+guid(owner);}
void ready(const GUID &owner)
{
    Handle event;event.value=OpenEventW(EVENT_MODIFY_STATE,FALSE,readyName(owner).c_str());
    check(event.value && SetEvent(event.value),"publish recovery fixture checkpoint");
    Sleep(INFINITE);
}
WindowsNetworkRecord fresh()
{
    WindowsProcess self(GetCurrentProcessId());
    return {uuid(),uuid(),self.identity(),self.identity(),std::nullopt,WindowsRecoveryPhase::Declared};
}
void parser()
{
    const auto record=fresh();
    const auto encoded=encodeWindowsNetworkRecord(record);
    check(encodeWindowsNetworkRecord(decodeWindowsNetworkRecord(encoded))==encoded,"null-DNS ownership roundtrip changed");
    auto withDns=record;
    withDns.dns=WindowsDnsRule::create({L"fixture.invalid"},address(L"192.0.2.53"));
    const auto populated=encodeWindowsNetworkRecord(withDns);
    check(encodeWindowsNetworkRecord(decodeWindowsNetworkRecord(populated))==populated,"DNS ownership roundtrip changed");
    using namespace winrt::Windows::Data::Json;
    for (const auto &field:{L"version",L"owner",L"adapter",L"caller",L"helper",L"dns",L"phase"}) {
        auto damaged=JsonObject::Parse(winrt::to_hstring(populated));damaged.Remove(field);
        refused([&]{decodeWindowsNetworkRecord(winrt::to_string(damaged.Stringify()));},"incomplete recovery record accepted");
    }
    for (const auto &bad:{std::string("{}"),std::string("null"),std::string("{broken"),std::string(WindowsNetworkContract::MaxRecordBytes+1,' ')})
        refused([&]{decodeWindowsNetworkRecord(bad);},"malformed recovery record accepted");
    auto damaged=JsonObject::Parse(winrt::to_hstring(populated));
    auto helper=damaged.GetNamedObject(L"helper");helper.SetNamedValue(L"created",JsonValue::CreateStringValue(L"01"));
    damaged.SetNamedValue(L"helper",helper);
    refused([&]{decodeWindowsNetworkRecord(winrt::to_string(damaged.Stringify()));},"noncanonical process identity accepted");
    damaged=JsonObject::Parse(winrt::to_hstring(populated));damaged.SetNamedValue(L"future",JsonValue::CreateBooleanValue(true));
    refused([&]{decodeWindowsNetworkRecord(winrt::to_string(damaged.Stringify()));},"unknown record fields accepted");
}
void lockBoundary()
{
    WindowsNetworkLock lock;
    Handle token;token.value=ordinaryWindowsToken();
    check(ImpersonateLoggedOnUser(token.value),"impersonate ordinary recovery client");
    bool denied=false;
    try {WindowsNetworkLock other;} catch(const std::system_error &error){denied=error.code().value()==ERROR_ACCESS_DENIED;}
    check(RevertToSelf(),"restore elevated fixture identity");
    check(denied,"ordinary client acquired privileged recovery lock");
}
void serviceBoundary()
{
    Handle token;token.value=ordinaryWindowsToken();
    check(ImpersonateLoggedOnUser(token.value),"impersonate ordinary service client");
    Service manager;manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);check(manager.value,"open fixture service manager");
    bool denied=true;
    const DWORD controls[]{SERVICE_START,SERVICE_STOP,SERVICE_CHANGE_CONFIG,WRITE_DAC,DELETE};
    for(const auto access:controls){
        Service service;service.value=OpenServiceW(manager.value,WindowsNetworkContract::Service,access);
        denied=denied && !service.value && GetLastError()==ERROR_ACCESS_DENIED;
    }
    Service read;read.value=OpenServiceW(manager.value,WindowsNetworkContract::Service,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS);
    const bool readable=read.value!=nullptr;
    check(RevertToSelf(),"restore fixture service identity");
    check(denied && readable,"ordinary client changed service authority or could not read service readiness");
}
void killService()
{
    Service manager,service;
    manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);check(manager.value,"open recovery service manager");
    service.value=OpenServiceW(manager.value,WindowsNetworkContract::Service,SERVICE_QUERY_STATUS);check(service.value,"open recovery service status");
    SERVICE_STATUS_PROCESS state{};DWORD size=0;
    check(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE *>(&state),sizeof(state),&size) && state.dwCurrentState==SERVICE_RUNNING && state.dwProcessId,"read actual recovery service PID");
    Handle process;process.value=OpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,FALSE,state.dwProcessId);
    check(process.value && TerminateProcess(process.value,1) && WaitForSingleObject(process.value,5000)==WAIT_OBJECT_0,"hard-kill real recovery service");
}
void writer(const GUID &owner,DWORD callerPid,const std::wstring &mode,const std::wstring &dll)
{
    auto record=fresh();record.owner=owner;
    WindowsProcess caller(callerPid);record.caller=caller.identity();
    auto domain=guid(owner);domain=domain.substr(1,36);
    for (auto &c:domain) c=static_cast<wchar_t>(towlower(c));
    record.dns=WindowsDnsRule::create({domain+L".invalid"},address(L"192.0.2.53"));
    WindowsNetworkRecovery recovery;recovery.declare(record);
    if(mode==L"declared")ready(owner);
    auto device=WindowsTunDevice::create(dll,record.adapter,address(L"192.0.2.1"),address(L"192.0.2.2"),1400,{},
        [&](const WindowsTunIdentity &identity){check(identity.guid==record.adapter,"device departed from persisted identity");if(mode==L"allocated")ready(owner);});
    record.dns->applySystem();ready(owner);
}
HKEY systemRule(const WindowsDnsRule &rule)
{
    // The fixture inspects the documented MS-GPNRPT local store independently of the implementation.
    const auto path=L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\"+guid(rule.id);
    HKEY key=nullptr;
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),REG_OPTION_OPEN_LINK,KEY_ALL_ACCESS|KEY_WOW64_64KEY,&key)==ERROR_SUCCESS,"open actual system NRPT rule");
    return key;
}
void server(HKEY key,const wchar_t *value)
{
    check(RegSetValueExW(key,L"GenericDNSServers",0,REG_SZ,reinterpret_cast<const BYTE *>(value),static_cast<DWORD>((wcslen(value)+1)*sizeof(wchar_t)))==ERROR_SUCCESS,"edit fixture-owned system NRPT rule");
}
void crash(const std::wstring &mode,const std::wstring &dll,bool externalChange,bool managed)
{
    const auto owner=uuid();
    Handle event,process,thread;
    event.value=CreateEventW(nullptr,TRUE,FALSE,readyName(owner).c_str());check(event.value,"create recovery checkpoint event");
    wchar_t executable[32768]{};
    const auto size=GetModuleFileNameW(nullptr,executable,32768);check(size && size<32768,"locate recovery fixture");
    std::wstring command=L"\""+std::wstring(executable)+L"\" --writer "+guid(owner)+L" "+std::to_wstring(GetCurrentProcessId())+L" "+mode+L" \""+dll+L"\"";
    STARTUPINFOW startup{sizeof(startup)};PROCESS_INFORMATION info{};
    check(CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&info),"start isolated ownership writer");
    process.value=info.hProcess;thread.value=info.hThread;
    struct Cleanup {
        HANDLE process;GUID owner;
        ~Cleanup(){
            if(WaitForSingleObject(process,0)==WAIT_TIMEOUT){TerminateProcess(process,1);WaitForSingleObject(process,5000);}
            try{WindowsNetworkRecovery recovery;const auto record=recovery.read(owner);if(record.dns)record.dns->restoreSystem();WindowsRegistryJournal journal;journal.remove(owner);}catch(...){}
        }
    } cleanup{process.value,owner};
    const HANDLE waits[]{event.value,process.value};
    check(WaitForMultipleObjects(2,waits,FALSE,30000)==WAIT_OBJECT_0,"writer failed to reach declared checkpoint");
    WindowsNetworkRecovery recovery;
    const auto record=recovery.read(owner);
    check(record.helper.pid==info.dwProcessId && record.caller.pid==GetCurrentProcessId(),"journal lost actual process owners");
    check(windowsAdapterPresent(record.adapter)==(mode!=L"declared"),"checkpoint has unexpected real device state");
    check(!recovery.restoreAbandoned(owner),"recovery competed with a live helper");
    Key rule;
    if(mode==L"active"){
        rule.value=systemRule(*record.dns);
        // Retain a separately opened handle across process death and conflict recovery.
        if(externalChange)server(rule.value,L"192.0.2.54");
    }
    if(managed && mode==L"allocated")killService();
    check(TerminateProcess(process.value,1) && WaitForSingleObject(process.value,5000)==WAIT_OBJECT_0,"hard-kill ownership writer");
    if(externalChange){
        if(managed){
            const auto deadline=GetTickCount64()+15000;
            while(recovery.read(owner).phase!=WindowsRecoveryPhase::Restoring){check(GetTickCount64()<deadline,"service did not attempt durable conflict recovery");Sleep(50);}
        }else refused([&]{recovery.restoreAbandoned(owner);},"external system DNS edit was deleted");
        wchar_t value[32]{};DWORD bytes=sizeof(value),type=0;
        check(RegQueryValueExW(rule.value,L"GenericDNSServers",nullptr,&type,reinterpret_cast<BYTE *>(value),&bytes)==ERROR_SUCCESS && std::wstring(value)==L"192.0.2.54","failed recovery changed external DNS");
        check(recovery.read(owner).phase==WindowsRecoveryPhase::Restoring,"conflict lost pending recovery intent");
        server(rule.value,L"192.0.2.53");
    }
    const auto deadline=GetTickCount64()+15000;
    while(managed?recovery.read(owner).phase!=WindowsRecoveryPhase::Restored:!recovery.restoreAbandoned(owner)) {check(GetTickCount64()<deadline,"owned device remained after helper death");Sleep(50);}
    check(!windowsAdapterPresent(record.adapter),"restored receipt precedes actual IP/PnP device removal");
    if(mode==L"active"){
        DWORD type=0;check(RegQueryValueExW(rule.value,L"Name",nullptr,&type,nullptr,nullptr)==ERROR_KEY_DELETED,"owned system DNS key survives restoration");
    }
    WindowsNetworkRecovery reopened;
    check(reopened.read(owner).phase==WindowsRecoveryPhase::Restored && reopened.restoreAbandoned(owner),"durable recovery receipt lost or not idempotent");
    refused([&]{reopened.acknowledge(owner,L"S-1-0-0");},"other account acknowledged recovery receipt");
    const auto next=fresh();
    refused([&]{reopened.declare(next);},"fresh UUID bypassed unconfirmed recovery receipt");
    reopened.acknowledge(owner,record.caller.sid);
    reopened.declare(next);
    WindowsRegistryJournal journal;journal.remove(next.owner);
    std::wcout<<L"PASS: "<<(managed?L"SCM independent":L"native")<<L" recovery at "<<mode<<(externalChange?L" with external DNS preservation":L"")<<L", persistent receipt and fresh UUID gate\n";
}
void ownedRelease(const std::wstring &dll,bool externalChange)
{
    auto record=fresh();
    auto domain=guid(record.owner).substr(1,36);for(auto &c:domain)c=static_cast<wchar_t>(towlower(c));
    record.dns=WindowsDnsRule::create({domain+L".invalid"},address(L"192.0.2.2"));
    WindowsNetworkRecovery recovery;recovery.declare(record);
    auto device=WindowsTunDevice::create(dll,record.adapter,address(L"192.0.2.1"),address(L"192.0.2.2"),1400,{},[](const auto &){});
    if(!externalChange){
        const WindowsTunPrefix target{address(L"198.18.0.6"),32};
        device->reconcile({target});
        MIB_IPFORWARD_ROW2 route{};InitializeIpForwardEntry(&route);
        route.InterfaceLuid=device->identity().luid;
        route.DestinationPrefix.Prefix.Ipv4.sin_family=AF_INET;route.DestinationPrefix.Prefix.Ipv4.sin_addr=target.address;
        route.DestinationPrefix.PrefixLength=target.bits;route.NextHop.Ipv4.sin_family=AF_INET;
        route.NextHop.Ipv4.sin_addr=address(L"192.0.2.2");
        check(GetIpForwardEntry2(&route)==NO_ERROR,"read actual owned capture");
        const auto original=route;++route.Metric;
        check(SetIpForwardEntry2(&route)==NO_ERROR,"edit fixture-owned capture metric");
        refused([&]{device->reconcile({target});},"externally edited capture was accepted");
        check(GetIpForwardEntry2(&route)==NO_ERROR && route.Metric==original.Metric+1,"refused reconciliation changed external route");
        check(SetIpForwardEntry2(&original)==NO_ERROR,"restore fixture-owned capture metric");
        device->reconcile({});
        const auto status=GetIpForwardEntry2(&route);
        check(status==ERROR_NOT_FOUND || status==ERROR_FILE_NOT_FOUND,"withdrawn capture remained installed");
        std::cout<<"PASS: actual capture reconciliation preserves external metric edits\n";
    }
    record.dns->applySystem();Key rule;rule.value=systemRule(*record.dns);
    WindowsRegistryJournal journal;
    auto replaced=record;++replaced.helper.created;journal.write(record.owner,encodeWindowsNetworkRecord(replaced));
    bool released=false;
    const auto release=[&]{released=true;device->close();restoreWindowsAdapter(record.adapter);};
    refused([&]{recovery.restoreOwned(record.owner,release);},"another helper identity released live ownership");
    check(!released && windowsAdapterPresent(record.adapter),"refused live release still changed its device");
    journal.write(record.owner,encodeWindowsNetworkRecord(record));
    if(externalChange){
        server(rule.value,L"192.0.2.54");
        refused([&]{recovery.restoreOwned(record.owner,release);},"live restore overwrote external DNS");
        check(released && !windowsAdapterPresent(record.adapter) && recovery.read(record.owner).phase==WindowsRecoveryPhase::Restoring,"foreign DNS prevented safe device release or lost recovery intent");
        server(rule.value,L"192.0.2.2");
    }
    check(recovery.restoreOwned(record.owner,[&]{
        DWORD type=0;check(RegQueryValueExW(rule.value,L"Name",nullptr,&type,nullptr,nullptr)==ERROR_KEY_DELETED,"device release preceded owned DNS release");release();
    }),"live owner did not publish its restored receipt");
    check(recovery.read(record.owner).phase==WindowsRecoveryPhase::Restored,"live release lost its durable receipt");
    recovery.acknowledge(record.owner,record.caller.sid);
    std::cout<<"PASS: live owned restore, helper identity, DNS-before-device release"<<(externalChange?" and foreign DNS preservation":"")<<'\n';
}
}

int wmain(int argc,wchar_t **argv) try
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    wchar_t guarded[8]{};
    check(GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","system recovery test requires disposable runner");
    if(argc==6 && std::wstring(argv[1])==L"--writer"){
        GUID owner{};check(SUCCEEDED(CLSIDFromString(argv[2],&owner)),"parse writer UUID");
        writer(owner,std::stoul(argv[3]),argv[4],argv[5]);return 0;
    }
    const bool managed=argc==3 && std::wstring(argv[1])==L"--service";
    check(argc==2 || managed,"recovery fixture requires the verified Wintun DLL");
    const auto dll=argv[managed?2:1];
    parser();lockBoundary();
    if(!managed){ownedRelease(dll,false);ownedRelease(dll,true);}
    if(managed)serviceBoundary();
    auto foreign=WindowsTunDevice::create(dll,uuid(),address(L"198.51.100.1"),address(L"198.51.100.2"),1400,{},[](const WindowsTunIdentity &){});
    for(const auto &mode:{L"declared",L"allocated",L"active"}){
        crash(mode,dll,false,managed);
        check(windowsAdapterPresent(foreign->identity().guid),"recovery removed another live Wintun device");
    }
    crash(L"active",dll,true,managed);
    check(windowsAdapterPresent(foreign->identity().guid),"conflict recovery removed another live Wintun device");
    return 0;
} catch(const winrt::hresult_error &error){std::cerr<<winrt::to_string(error.message())<<'\n';return 1;}
catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
