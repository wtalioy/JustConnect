#include <winsock2.h>
#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include "infrastructure/networkhelper/windows/installation.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "ordinarytoken.h"
#include "controlhandoff.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <iphlpapi.h>
#include <set>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <iostream>
#include <thread>
#include <exception>
#include <system_error>

using namespace winrt::Windows::Data::Json;
namespace {
constexpr DWORD FixtureTimeoutMs=45000;
void check(bool value,const char *stage){if(!value)throw std::runtime_error(stage);}
struct ExitAddress {
    MIB_UNICASTIPADDRESS_ROW row{};
    std::set<ULONG> before;
    bool added=false;
    ~ExitAddress(){if(added && DeleteUnicastIpAddressEntry(&row)!=NO_ERROR)std::cerr<<"exit fixture address cleanup failed\n";}
    static std::set<ULONG> addresses(NET_IFINDEX index=0){
        MIB_UNICASTIPADDRESS_TABLE *table=nullptr;
        check(GetUnicastIpAddressTable(AF_INET,&table)==NO_ERROR,"read actual exit addresses");
        std::set<ULONG> values;
        for(ULONG i=0;i<table->NumEntries;++i)if(!index || table->Table[i].InterfaceIndex==index)
            values.insert(ntohl(table->Table[i].Address.Ipv4.sin_addr.s_addr));
        FreeMibTable(table);return values;
    }
    ULONG apply(NET_IFINDEX index){
        MIB_IF_ROW2 adapter{};adapter.InterfaceIndex=index;
        check(index && GetIfEntry2(&adapter)==NO_ERROR && adapter.OperStatus==IfOperStatusUp && adapter.Type!=IF_TYPE_SOFTWARE_LOOPBACK,
            "changed exit is an actual active original interface");
        MIB_IPFORWARD_TABLE2 *routes=nullptr;
        check(GetIpForwardTable2(AF_INET,&routes)==NO_ERROR,"read actual original default routes");
        bool isDefault=false;
        for(ULONG i=0;i<routes->NumEntries;++i)isDefault|=routes->Table[i].InterfaceIndex==index && routes->Table[i].DestinationPrefix.PrefixLength==0;
        FreeMibTable(routes);check(isDefault,"changed exit carries an actual default route");
        before=addresses(index);const auto used=addresses();ULONG selected=0;
        // RFC 5737 addresses are fixture inputs; no existing address or default route is replaced.
        for(ULONG host=1;host<255;++host){const auto candidate=(192u<<24)|(2u<<8)|host;if(!used.contains(candidate)){selected=candidate;break;}}
        check(selected && !before.empty(),"unused documentation alias and original exit addresses");
        InitializeUnicastIpAddressEntry(&row);row.InterfaceIndex=index;row.Address.Ipv4.sin_family=AF_INET;
        row.Address.Ipv4.sin_addr.s_addr=htonl(selected);row.OnLinkPrefixLength=32;row.SkipAsSource=TRUE;row.DadState=IpDadStatePreferred;
        check(CreateUnicastIpAddressEntry(&row)==NO_ERROR,"add external exit address alias");added=true;
        check(GetUnicastIpAddressEntry(&row)==NO_ERROR && row.DadState==IpDadStatePreferred && row.SkipAsSource && row.OnLinkPrefixLength==32,
            "external exit alias is usable without changing automatic source selection");
        auto expected=before;expected.insert(selected);check(addresses(index)==expected,"external alias preserves prior exit addresses");return selected;
    }
    void restore(){
        auto expected=before;expected.insert(ntohl(row.Address.Ipv4.sin_addr.s_addr));
        check(added && addresses(row.InterfaceIndex)==expected,"application restoration preserves the external alias");
        check(DeleteUnicastIpAddressEntry(&row)==NO_ERROR,"remove only the fixture exit alias");added=false;
        check(addresses(row.InterfaceIndex)==before,"fixture restores complete original exit address inventory");
    }
};
struct Handle {HANDLE value=nullptr;~Handle(){if(value)CloseHandle(value);}};
struct Process {
    Handle process,thread;
    ~Process(){if(process.value && WaitForSingleObject(process.value,0)==WAIT_TIMEOUT){TerminateProcess(process.value,1);WaitForSingleObject(process.value,5000);}}
    void start(std::wstring command,HANDLE token=nullptr,STARTUPINFOW *configured=nullptr){
        STARTUPINFOW startup{sizeof(startup)};PROCESS_INFORMATION info{};
        const auto ok=token?CreateProcessAsUserW(token,nullptr,command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,configured,&info)
            :CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&info);
        check(ok,"launch control fixture process");process.value=info.hProcess;thread.value=info.hThread;
    }
    DWORD wait(){
        check(WaitForSingleObject(process.value,FixtureTimeoutMs)==WAIT_OBJECT_0,"control fixture process deadline");
        DWORD code=1;check(GetExitCodeProcess(process.value,&code),"control fixture exit");return code;
    }
};
GUID uuid(){GUID id{};check(SUCCEEDED(CoCreateGuid(&id)),"new control UUID");return id;}
std::wstring guid(const GUID &id){wchar_t value[39]{};check(StringFromGUID2(id,value,39)!=0,"control UUID text");return value;}
std::wstring executable(){wchar_t value[32768]{};const auto size=GetModuleFileNameW(nullptr,value,32768);check(size && size<32768,"control fixture image");return value;}
using Input=WindowsControlFixtureInput;
void transfer(HANDLE pipe,void *data,DWORD size,bool write){
    DWORD count=0;check((write?WriteFile(pipe,data,size,&count,nullptr):ReadFile(pipe,data,size,&count,nullptr)) && count==size,"control fixture handoff");
}
void awaitInput(HANDLE pipe,DWORD size,const Process &sender,DWORD timeout,const char *stage){
    const auto deadline=GetTickCount64()+timeout;DWORD available=0;
    for(;;){
        check(PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr),stage);
        if(available>=size)return;
        check(GetTickCount64()<deadline && WaitForSingleObject(sender.process.value,0)==WAIT_TIMEOUT,stage);Sleep(10);
    }
}
JsonObject command(const GUID &session,const wchar_t *operation,const GUID &owner={}){
    JsonObject value;
    value.SetNamedValue(L"version",JsonValue::CreateNumberValue(WindowsNetworkContract::Protocol));
    value.SetNamedValue(L"session",JsonValue::CreateStringValue(guid(session)));
    value.SetNamedValue(L"operation",JsonValue::CreateStringValue(operation));
    value.SetNamedValue(L"owner",owner==GUID{}?JsonValue::CreateNullValue():JsonValue::CreateStringValue(guid(owner)));
    return value;
}
JsonObject exchange(WindowsPacketPipe &pipe,const GUID &session,const wchar_t *operation,const GUID &owner={}){
    sendWindowsControlMessage(pipe,winrt::to_string(command(session,operation,owner).Stringify()));
    if(std::wstring(operation)==L"close")Sleep(50); // The reply must survive a delayed consumer.
    const auto reply=JsonObject::Parse(winrt::to_hstring(receiveWindowsControlMessage(pipe,WindowsNetworkContract::ControlTimeoutMs)));
    check(reply.GetNamedNumber(L"version")==WindowsNetworkContract::Protocol && reply.GetNamedString(L"session")==guid(session)
        && reply.GetNamedString(L"operation")==operation,"control response escaped its request");
    if(std::wstring(operation)==L"close"){const unsigned char received=1;pipe.write(&received,1,5000);}
    return reply;
}
bool contains(const JsonObject &reply,const GUID &owner){
    for(const auto &item:reply.GetNamedArray(L"owners"))if(item.GetObject().GetNamedString(L"owner")==guid(owner))return true;
    return false;
}
int client(const GUID &session,const std::wstring &mode){
    Handle token;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value),"inspect actual control client token");
    TOKEN_ELEVATION elevation{};DWORD size=0;
    check(GetTokenInformation(token.value,TokenElevation,&elevation,sizeof(elevation),&size) && !elevation.TokenIsElevated,"control client must remain ordinary");
    Input input;transfer(GetStdHandle(STD_INPUT_HANDLE),&input,sizeof(input),false);
    Handle server;server.value=reinterpret_cast<HANDLE>(input.server);
    if(mode==L"authorize" || mode==L"authorize-cancel" || mode==L"authorize-replaced"){
        Handle captured,writer;check(CreatePipe(&captured.value,&writer.value,nullptr,0),"capture native authorization result");
        const auto original=GetStdHandle(STD_OUTPUT_HANDLE);check(SetStdHandle(STD_OUTPUT_HANDLE,writer.value),"redirect authorization result");
        WindowsProcess self(GetCurrentProcessId());bool called=false;
        const auto code=WindowsHelperInstallation::authorizeControl(self.identity().pid,self.identity().created+(mode==L"authorize-replaced"?1:0),session,
            [&](const auto &image,const auto &parameters)->HANDLE{
                called=true;check(image==executable() && parameters==L"--control "+std::to_wstring(self.identity().pid)+L" "+std::to_wstring(self.identity().created)+L" "+guid(session),"authorization changed its fixed launch target");
                if(mode==L"authorize-cancel"){SetLastError(ERROR_CANCELLED);return nullptr;}
                HANDLE duplicate=nullptr;check(DuplicateHandle(GetCurrentProcess(),server.value,GetCurrentProcess(),&duplicate,0,FALSE,DUPLICATE_SAME_ACCESS),"retain approved authorization result");return duplicate;
            });
        check(SetStdHandle(STD_OUTPUT_HANDLE,original),"restore control test console");
        char bytes[1024]{};DWORD size=0;check(ReadFile(captured.value,bytes,sizeof(bytes),&size,nullptr) && size,"read authorization result");
        const auto result=JsonObject::Parse(winrt::to_hstring(std::string(bytes,size)));
        check(result.Size()==4 && result.GetNamedString(L"session")==guid(session) && result.GetNamedNumber(L"version")==WindowsNetworkContract::Protocol,"authorization response escaped its session");
        if(mode!=L"authorize"){
            check(code==1 && result.GetNamedString(L"handle")==L"0" && result.GetNamedNumber(L"error")== (mode==L"authorize-cancel"?ERROR_CANCELLED:ERROR_ACCESS_DENIED),"authorization refusal lost its error or transferred a handle");
            check(called==(mode==L"authorize-cancel"),"replaced caller reached elevation");return 0;
        }
        check(code==0 && called && result.GetNamedNumber(L"error")==0,"authorization did not return the approved process");
        const auto value=std::stoull(std::wstring(result.GetNamedString(L"handle").c_str()));
        Handle approved;approved.value=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value));
        check(approved.value!=server.value && GetProcessId(approved.value)==GetProcessId(server.value),"authorization transferred another process identity");
        CloseHandle(server.value);server.value=approved.value;approved.value=nullptr;
    }
    if(mode==L"replaced"){
        bool denied=false;try{WindowsPacketPipe::connect(windowsControlPipeName(session),server.value,5000);}catch(const std::system_error &){denied=true;}
        check(denied,"replaced caller was accepted");return 0;
    }
    if(mode==L"server-mismatch"){
        bool denied=false;try{WindowsPacketPipe::connect(windowsControlPipeName(session),server.value,5000);}catch(const std::system_error &error){denied=error.code().value()==ERROR_ACCESS_DENIED;}
        check(denied,"unexpected server accepted before request disclosure");return 0;
    }
    auto pipe=WindowsPacketPipe::connect(windowsControlPipeName(session),server.value,5000);
    if(mode==L"io-timeout"){
        unsigned char byte=0;bool timedOut=false;
        try{pipe->read(&byte,1,20);}catch(const std::system_error &error){timedOut=error.code().value()==ERROR_TIMEOUT;}
        check(timedOut,"pending control I/O was not cancelled at its deadline");return 0;
    }
    if(mode==L"oversized"){
        const auto size=WindowsNetworkContract::MaxMessageBytes+1;
        unsigned char length[]{static_cast<unsigned char>(size>>24),static_cast<unsigned char>(size>>16),static_cast<unsigned char>(size>>8),static_cast<unsigned char>(size)};
        pipe->write(length,4,5000);
    }else if(mode!=L"normal" && mode!=L"authorize" && mode!=L"eof"){
        auto request=command(session,L"inspect");
        if(mode==L"session-mismatch")request.SetNamedValue(L"session",JsonValue::CreateStringValue(guid(uuid())));
        else if(mode==L"unknown-field")request.SetNamedValue(L"path",JsonValue::CreateStringValue(L"C:\\unowned"));
        else request.SetNamedValue(L"operation",JsonValue::CreateStringValue(L"execute"));
        sendWindowsControlMessage(*pipe,winrt::to_string(request.Stringify()));
    }else if(mode==L"eof"){return 0;}
    else{
        auto reply=exchange(*pipe,session,L"inspect");
        check(reply.GetNamedBoolean(L"ok") && contains(reply,input.dead) && contains(reply,input.live) && !contains(reply,input.foreign),"control inspection crossed account ownership");
        check(exchange(*pipe,session,L"recover",input.dead).GetNamedBoolean(L"ok"),"owned abandoned recovery refused");
        check(exchange(*pipe,session,L"acknowledge",input.dead).GetNamedBoolean(L"ok"),"owned restored receipt refused");
        reply=exchange(*pipe,session,L"inspect");check(reply.GetNamedBoolean(L"ok") && !contains(reply,input.dead),"acknowledged receipt still listed");
        reply=exchange(*pipe,session,L"recover",input.live);check(!reply.GetNamedBoolean(L"ok") && reply.GetNamedNumber(L"error")==ERROR_BUSY,"live owner recovered through control");
        check(!exchange(*pipe,session,L"acknowledge",input.live).GetNamedBoolean(L"ok"),"live receipt removed through control");
        for(const auto operation:{L"recover",L"acknowledge"}){
            reply=exchange(*pipe,session,operation,input.foreign);
            check(!reply.GetNamedBoolean(L"ok") && reply.GetNamedNumber(L"error")==ERROR_ACCESS_DENIED,"foreign account receipt accepted through control");
        }
        check(exchange(*pipe,session,L"close").GetNamedBoolean(L"ok"),"control close failed");
        check(WaitForSingleObject(server.value,5000)==WAIT_OBJECT_0,"acknowledged control did not exit");return 0;
    }
    bool refused=false;try{receiveWindowsControlMessage(*pipe,5000);}catch(const std::system_error &){refused=true;}
    check(refused,"unsafe control request returned a reply");return 0;
}
GUID scenario(const std::wstring &helper,const std::wstring &mode,const std::wstring &clientImage={},bool application=false,
    const std::wstring &fault={},std::optional<WindowsNetworkFingerprint> *baseline=nullptr,bool exitChange=false){
    auto session=uuid();
    Handle token,input,childInput,console,request,childRequest;
    token.value=ordinaryWindowsToken();
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};
    check(CreatePipe(&childInput.value,&input.value,&attributes,0) && SetHandleInformation(input.value,HANDLE_FLAG_INHERIT,0),"control fixture input pipe");
    check(DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_OUTPUT_HANDLE),GetCurrentProcess(),&console.value,0,TRUE,DUPLICATE_SAME_ACCESS),"control fixture console");
    STARTUPINFOW startup{sizeof(startup)};startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=childInput.value;startup.hStdOutput=console.value;startup.hStdError=console.value;
    if(application)check(CreatePipe(&request.value,&childRequest.value,&attributes,0) && SetHandleInformation(request.value,HANDLE_FLAG_INHERIT,0),"application approval request pipe");
    const auto reply=application?L" "+std::to_wstring(reinterpret_cast<std::uintptr_t>(childRequest.value))+(fault.empty()?L"":L" "+fault):L"";
    Process gui;gui.start(L"\""+(clientImage.empty()?executable():clientImage)+L"\" --client "+guid(session)+L" "+mode+reply,token.value,&startup);
    CloseHandle(childInput.value);childInput.value=nullptr;
    if(application){
        CloseHandle(childRequest.value);childRequest.value=nullptr;
        awaitInput(request.value,sizeof(session),gui,WindowsNetworkContract::ControlTimeoutMs,"application did not request approval before its deadline");
        transfer(request.value,&session,sizeof(session),false);check(session!=GUID{},"actual application attempt UUID");
    }
    WindowsProcess caller(GetProcessId(gui.process.value)),current(GetCurrentProcessId());
    WindowsRegistryJournal journal;Input payload;
    payload.dead=uuid();payload.live=uuid();payload.foreign=uuid();
    if(baseline && *baseline){payload.baseline=**baseline;payload.hasBaseline=true;}
    struct Cleanup {
        WindowsRegistryJournal &journal;Input &input;GUID session;std::wstring sid;bool network,done=false;
        ~Cleanup(){
            if(done)return;
            if(network){
                try{WindowsNetworkRecovery recovery;if(recovery.restoreAbandoned(session))recovery.acknowledge(session,sid);}
                catch(const std::system_error &error){if(error.code().value()!=ERROR_FILE_NOT_FOUND)std::cerr<<"session fixture cleanup: "<<error.what()<<'\n';}
                return;
            }
            try{WindowsNetworkLock lock;for(const auto &id:{input.dead,input.live,input.foreign}){try{journal.remove(id);}catch(...){}}}
            catch(const std::exception &error){std::cerr<<"control fixture cleanup: "<<error.what()<<'\n';}
        }
    } cleanup{journal,payload,session,caller.identity().sid,mode==L"network"};
    auto record=WindowsNetworkRecord{payload.live,uuid(),caller.identity(),current.identity(),{},WindowsRecoveryPhase::Declared};
    const auto liveRecord=encodeWindowsNetworkRecord(record);
    record.owner=payload.dead;record.adapter=uuid();--record.helper.created;
    const auto deadRecord=encodeWindowsNetworkRecord(record);
    record.owner=payload.foreign;record.adapter=uuid();record.caller.sid=L"S-1-5-18";record.phase=WindowsRecoveryPhase::Restored;
    const auto foreignRecord=encodeWindowsNetworkRecord(record);
    if(mode!=L"network"){
        WindowsNetworkLock lock;
        journal.write(payload.live,liveRecord);journal.write(payload.dead,deadRecord);journal.write(payload.foreign,foreignRecord);
    }
    Process elevated;
    if(mode==L"server-mismatch" || mode==L"authorize-cancel" || mode==L"authorize-replaced")elevated.start(L"\""+executable()+L"\" --idle");
    else elevated.start(L"\""+helper+L"\" --control "+std::to_wstring(caller.identity().pid)+L" "+std::to_wstring(caller.identity().created+(mode==L"replaced"?1:0))+L" "+guid(session));
    HANDLE retained=nullptr;
    check(DuplicateHandle(GetCurrentProcess(),elevated.process.value,gui.process.value,&retained,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0),"handoff actual elevated process object");
    payload.server=reinterpret_cast<std::uintptr_t>(retained);
    if(mode==L"server-mismatch"){
        std::exception_ptr error;
        std::jthread fake([&]{try{auto pipe=WindowsPacketPipe::listen(windowsControlPipeName(session),caller,5000);unsigned char byte=0;bool closed=false;try{pipe->read(&byte,1,5000);}catch(const std::system_error &){closed=true;}check(closed,"client disclosed a byte to a counterfeit server");}catch(...){error=std::current_exception();}});
        transfer(input.value,&payload,sizeof(payload),true);
        const auto code=gui.wait();fake.join();if(error)std::rethrow_exception(error);check(code==0,"ordinary client accepted fake server");
    }else{
        transfer(input.value,&payload,sizeof(payload),true);
        if(exitChange){
            check(fault.empty(),"exit change uses normal ownership restoration");
            WindowsExitChangeFixtureInput changed;
            awaitInput(request.value,sizeof(changed),gui,FixtureTimeoutMs,"application did not reach the original exit change boundary");
            transfer(request.value,&changed,sizeof(changed),false);
            ExitAddress alias;changed.address=alias.apply(changed.interfaceIndex);
            const auto absent=[&](const GUID &owner){try{journal.read(owner);}catch(const std::system_error &error){if(error.code().value()==ERROR_FILE_NOT_FOUND)return true;throw;}return false;};
            const auto previous=session;const auto deadline=GetTickCount64()+FixtureTimeoutMs;
            while(!absent(previous) || WaitForSingleObject(elevated.process.value,0)!=WAIT_OBJECT_0){
                check(GetTickCount64()<deadline && WaitForSingleObject(gui.process.value,0)==WAIT_TIMEOUT,"changed exit did not release old responsibility before reconnect");Sleep(10);
            }
            check(elevated.wait()==0,"old authorized helper exits after complete restoration");
            transfer(input.value,&changed,sizeof(changed),true);
            awaitInput(request.value,sizeof(session),gui,WindowsNetworkContract::ControlTimeoutMs,"reconnect did not request a fresh authorization");
            transfer(request.value,&session,sizeof(session),false);check(session!=GUID{} && session!=previous,"reconnect uses a fresh ownership UUID");cleanup.session=session;
            Process reconnected;
            reconnected.start(L"\""+helper+L"\" --control "+std::to_wstring(caller.identity().pid)+L" "+std::to_wstring(caller.identity().created)+L" "+guid(session));
            retained=nullptr;
            check(DuplicateHandle(GetCurrentProcess(),reconnected.process.value,gui.process.value,&retained,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0),"handoff fresh authorized helper process");
            payload.server=reinterpret_cast<std::uintptr_t>(retained);transfer(input.value,&payload,sizeof(payload),true);
            unsigned char complete=0;
            awaitInput(request.value,1,gui,FixtureTimeoutMs,"reconnected application did not finish real traffic and ordered restoration");
            transfer(request.value,&complete,1,false);
            check(complete==1 && reconnected.wait()==0 && absent(previous) && absent(session),"both exit generations restore and acknowledge their complete ownership");
            alias.restore();transfer(input.value,&complete,1,true);
            check(gui.wait()==0,"application did not confirm original DNS and interface restoration after the exit change");
            std::cout<<"PASS: actual Windows exit address change, old ownership release, fresh authorization and preserved external address\n";
        }else if(!fault.empty()){
            check(application && baseline,"fault injection requires the ordinary application fixture");
            WindowsNetworkFingerprint original;
            awaitInput(request.value,sizeof(original),gui,FixtureTimeoutMs,"application did not finish actual traffic before the fault");
            transfer(request.value,&original,sizeof(original),false);*baseline=original;
            WindowsNetworkRecovery recovery;
            const auto active=recovery.read(session);
            check(active.phase==WindowsRecoveryPhase::Declared && active.adapter!=GUID{} && active.dns.has_value(),"real active device and DNS precede the crash");
            check(TerminateProcess(elevated.process.value,1),"kill actual privileged network helper");
            if(fault==L"dual-kill")check(TerminateProcess(gui.process.value,1),"kill actual Qt/core host");
            check(elevated.wait()==1,"privileged helper terminated without normal restoration");
            const auto deadline=GetTickCount64()+FixtureTimeoutMs;
            while(recovery.read(session).phase!=WindowsRecoveryPhase::Restored){check(GetTickCount64()<deadline,"SCM did not independently restore the crashed application");Sleep(50);}
            if(fault==L"helper-loss"){unsigned char restored=1;transfer(input.value,&restored,1,true);}
            check(gui.wait()==(fault==L"dual-kill"?1:0),"ordinary application failed its helper-loss contract");
        }else check(gui.wait()==0,"ordinary control client failed");
        if(!exitChange && fault.empty() && mode!=L"authorize-cancel" && mode!=L"authorize-replaced"){
            const auto code=elevated.wait();check(code==(mode==L"normal" || mode==L"authorize" || mode==L"network"?0:1),"control helper accepted an invalid session");
        }
    }
    if(mode!=L"network")check(journal.read(payload.live)==liveRecord && journal.read(payload.foreign)==foreignRecord,"control modified live or foreign ownership");
    else if(fault.empty()){bool absent=false;try{journal.read(session);}catch(const std::system_error &error){absent=error.code().value()==ERROR_FILE_NOT_FOUND;}check(absent,"normal network stop left an unacknowledged record");}
    if(mode!=L"network"){
        WindowsNetworkLock lock;
        for(const auto &id:{payload.dead,payload.live,payload.foreign})journal.remove(id);
    }
    cleanup.done=true;
    std::wcout<<L"PASS: native authenticated control "<<mode<<L'\n';
    return session;
}
}

int wmain(int argc,wchar_t **argv) try
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    if(argc==2 && std::wstring(argv[1])==L"--idle"){Sleep(60000);return 0;}
    if(argc==4 && std::wstring(argv[1])==L"--client"){
        GUID session{};check(SUCCEEDED(CLSIDFromString(argv[2],&session)),"client session UUID");return client(session,argv[3]);
    }
    wchar_t guarded[8]{};
    const bool qt=argc==4 && std::wstring(argv[1])==L"--qt";
    const bool application=argc==4 && std::wstring(argv[1])==L"--qt-session";
    check((argc==2 || qt || application) && GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","control mutation requires disposable runner");
    if(application){
        wchar_t faults[8]{};
        if(GetEnvironmentVariableW(L"JC_WINDOWS_SESSION_FAULTS",faults,8)==4 && std::wstring(faults)==L"true"){
            std::optional<WindowsNetworkFingerprint> baseline;
            const auto lost=scenario(argv[2],L"network",argv[3],true,L"helper-loss",&baseline);
            const auto killed=scenario(argv[2],L"network",argv[3],true,L"dual-kill",&baseline);
            scenario(argv[2],L"network",argv[3],true,{},&baseline);
            WindowsRegistryJournal journal;
            for(const auto &owner:{lost,killed}){
                bool absent=false;try{journal.read(owner);}catch(const std::system_error &error){absent=error.code().value()==ERROR_FILE_NOT_FOUND;}
                check(absent,"new application did not acknowledge the prior crash receipt");
            }
            std::cout<<"PASS: ordinary application helper-loss, double crash, SCM recovery, complete baseline and new-session receipt handoff\n";return 0;
        }
    }
    if(qt || application){
        wchar_t changed[8]{};
        const bool exitChange=application && GetEnvironmentVariableW(L"JC_WINDOWS_SESSION_EXIT_CHANGE",changed,8)==4 && std::wstring(changed)==L"true";
        scenario(argv[2],application?L"network":L"normal",argv[3],application,{},nullptr,exitChange);
        if(!exitChange)scenario(argv[2],L"network",argv[3],application);
        return 0;
    }
    for(const auto mode:{L"normal",L"authorize",L"authorize-cancel",L"authorize-replaced",L"server-mismatch",L"replaced",L"session-mismatch",L"unknown-field",L"unknown-operation",L"oversized",L"io-timeout",L"eof"})scenario(argv[1],mode);
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
