#include "infrastructure/networkhelper/windows/control.h"
#include "infrastructure/networkhelper/windows/recovery.h"
#include "infrastructure/packetpipe/windows/stream.h"
#include "ordinarytoken.h"
#include "windowsnetworkcontract.h"
#include <objbase.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <iostream>
#include <thread>
#include <exception>
#include <system_error>

using namespace winrt::Windows::Data::Json;
namespace {
void check(bool value,const char *stage){if(!value)throw std::runtime_error(stage);}
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
        check(WaitForSingleObject(process.value,45000)==WAIT_OBJECT_0,"control fixture process deadline");
        DWORD code=1;check(GetExitCodeProcess(process.value,&code),"control fixture exit");return code;
    }
};
GUID uuid(){GUID id{};check(SUCCEEDED(CoCreateGuid(&id)),"new control UUID");return id;}
std::wstring guid(const GUID &id){wchar_t value[39]{};check(StringFromGUID2(id,value,39)!=0,"control UUID text");return value;}
std::wstring executable(){wchar_t value[32768]{};const auto size=GetModuleFileNameW(nullptr,value,32768);check(size && size<32768,"control fixture image");return value;}
struct Input {std::uintptr_t server=0;GUID dead{},live{},foreign{};};
void transfer(HANDLE pipe,void *data,DWORD size,bool write){
    DWORD count=0;check((write?WriteFile(pipe,data,size,&count,nullptr):ReadFile(pipe,data,size,&count,nullptr)) && count==size,"control fixture handoff");
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
    const auto reply=JsonObject::Parse(winrt::to_hstring(receiveWindowsControlMessage(pipe,WindowsNetworkContract::ControlTimeoutMs)));
    check(reply.GetNamedNumber(L"version")==WindowsNetworkContract::Protocol && reply.GetNamedString(L"session")==guid(session)
        && reply.GetNamedString(L"operation")==operation,"control response escaped its request");return reply;
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
    }else if(mode!=L"normal" && mode!=L"eof"){
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
        check(exchange(*pipe,session,L"close").GetNamedBoolean(L"ok"),"control close failed");return 0;
    }
    bool refused=false;try{receiveWindowsControlMessage(*pipe,5000);}catch(const std::system_error &){refused=true;}
    check(refused,"unsafe control request returned a reply");return 0;
}
void scenario(const std::wstring &helper,const std::wstring &mode){
    const auto session=uuid();
    Handle token,input,childInput,console;
    token.value=ordinaryWindowsToken();
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};
    check(CreatePipe(&childInput.value,&input.value,&attributes,0) && SetHandleInformation(input.value,HANDLE_FLAG_INHERIT,0),"control fixture input pipe");
    check(DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_OUTPUT_HANDLE),GetCurrentProcess(),&console.value,0,TRUE,DUPLICATE_SAME_ACCESS),"control fixture console");
    STARTUPINFOW startup{sizeof(startup)};startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=childInput.value;startup.hStdOutput=console.value;startup.hStdError=console.value;
    Process gui;gui.start(L"\""+executable()+L"\" --client "+guid(session)+L" "+mode,token.value,&startup);
    CloseHandle(childInput.value);childInput.value=nullptr;
    WindowsProcess caller(GetProcessId(gui.process.value)),current(GetCurrentProcessId());
    WindowsRegistryJournal journal;Input payload;
    payload.dead=uuid();payload.live=uuid();payload.foreign=uuid();
    struct Cleanup {WindowsRegistryJournal &journal;Input &input;~Cleanup(){for(const auto &id:{input.dead,input.live,input.foreign}){try{journal.remove(id);}catch(...){}}}} cleanup{journal,payload};
    auto record=WindowsNetworkRecord{payload.live,uuid(),caller.identity(),current.identity(),{},WindowsRecoveryPhase::Declared};
    journal.write(record.owner,encodeWindowsNetworkRecord(record));
    const auto liveRecord=encodeWindowsNetworkRecord(record);
    record.owner=payload.dead;record.adapter=uuid();--record.helper.created;
    journal.write(record.owner,encodeWindowsNetworkRecord(record));
    record.owner=payload.foreign;record.adapter=uuid();record.caller.sid=L"S-1-5-18";record.phase=WindowsRecoveryPhase::Restored;
    journal.write(record.owner,encodeWindowsNetworkRecord(record));
    const auto foreignRecord=encodeWindowsNetworkRecord(record);
    Process elevated;
    if(mode==L"server-mismatch")elevated.start(L"\""+executable()+L"\" --idle");
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
        check(gui.wait()==0,"ordinary control client failed");
        const auto code=elevated.wait();check(code==(mode==L"normal"?0:1),"control helper accepted an invalid session");
    }
    check(journal.read(payload.live)==liveRecord && journal.read(payload.foreign)==foreignRecord,"control modified live or foreign ownership");
    std::wcout<<L"PASS: native authenticated control "<<mode<<L'\n';
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
    check(argc==2 && GetEnvironmentVariableW(L"GITHUB_ACTIONS",guarded,8)==4 && std::wstring(guarded)==L"true","control mutation requires disposable runner");
    for(const auto mode:{L"normal",L"server-mismatch",L"replaced",L"session-mismatch",L"unknown-field",L"unknown-operation",L"oversized",L"io-timeout",L"eof"})scenario(argv[1],mode);
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
